#ifndef _zkMTACircuit_h
#define _zkMTACircuit_h

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using namespace libsnark;


/*
 * Constrains an n-bit attribute `attr` to be in a range given
 * by n-bit integers `upper_bound` and `lower_bound`.
*/
template<typename FieldT>
class zkrange_gadget : gadget<FieldT> {
private:
    std::shared_ptr<comparison_gadget<FieldT>> upper;
    std::shared_ptr<comparison_gadget<FieldT>> lower;
    pb_linear_combination<FieldT> attribute;

public:
    zkrange_gadget(protoboard<FieldT> &pb,
                   size_t n,
                   const pb_linear_combination<FieldT> &upper_bound,
                   const pb_linear_combination<FieldT> &lower_bound,
                   const pb_linear_combination<FieldT> &attribute)
        : gadget<FieldT>(pb), attribute(attribute)
        {
            // Generate dummy variables for LT, we only care about LE
            // we won't further constrain lt1, lt2 so we can simply discard them after allocation.
            pb_variable<FieldT> lt1, lt2;
            lt1.allocate(pb);
            lt2.allocate(pb);

            // Constrain `attribute <= upper_bound`
            upper.reset(new comparison_gadget<FieldT>(pb, n, attribute, upper_bound, lt1, ONE));

            //Constrain `lower_bound <= attribute`
            lower.reset(new comparison_gadget<FieldT>(pb, n, lower_bound, attribute, lt2, ONE));
        }
    void generate_r1cs_constraints(){
        upper->generate_r1cs_constraints();
        lower->generate_r1cs_constraints();
    }
    void generate_r1cs_witness(){
        upper->generate_r1cs_witness();
        lower->generate_r1cs_witness();
    }
};

// Constrains a leaf with hash leaf_digest to be in a merkle tree
// with root root_digest and depth tree_depth
template<typename FieldT, typename HashT>
class zkmta_gadget : gadget<FieldT>{
private:
    pb_variable_array<FieldT> packed_inputs;
    pb_variable_array<FieldT> unpacked_inputs;
    pb_variable_array<FieldT> address_bits_va;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<digest_variable<FieldT>> root_digest;
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;
    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> merkle_check;

public:
    zkmta_gadget(protoboard<FieldT> &pb, size_t tree_depth) : gadget<FieldT>(pb)
        {
            size_t digest_len = HashT::get_digest_len();
            // Packed digest takes ceil(diget_len/capacity) field elements to store
            size_t digest_field_elem_len = (digest_len + FieldT::capacity() - 1)/FieldT::capacity();
            packed_inputs.allocate(pb, digest_field_elem_len);
            pb.set_input_sizes(digest_field_elem_len);

            address_bits_va.allocate(pb, tree_depth, "address_bits");
            root_digest.reset(new digest_variable<FieldT>(pb, digest_len, "output_digest"));
            unpacked_inputs = root_digest->bits;
            unpacker.reset(new multipacking_gadget<FieldT>(pb,
                                                           unpacked_inputs,
                                                           packed_inputs,
                                                           FieldT::capacity(),
                                                           "multipacker"
                                                           ));

            leaf_digest.reset(new digest_variable<FieldT>(pb, digest_len, "input_block"));
            path_var.reset(new merkle_authentication_path_variable<FieldT, HashT>(pb, tree_depth, "path_var"));
            merkle_check.reset(new merkle_tree_check_read_gadget<FieldT, HashT>
                               (pb, tree_depth, address_bits_va,
                                *leaf_digest, *root_digest, *path_var, ONE, "ml"));

        }

    void generate_r1cs_constraints()
    {
        unpacker->generate_r1cs_constraints(true);
        root_digest->generate_r1cs_constraints();
        leaf_digest->generate_r1cs_constraints();
        path_var->generate_r1cs_constraints();
        merkle_check->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(libff::bit_vector &leaf,
                               libff::bit_vector &root,
                               libff::bit_vector& address_bits,
                               size_t &address,
                               std::vector<libsnark::merkle_authentication_node> &auth_path)
    {
        // Pack merkle root into 2 field elements
        std::vector<FieldT> root_elems = libff::pack_bit_vector_into_field_element_vector<FieldT>(root);
        packed_inputs.fill_with_field_elements(this->pb, root_elems);

        address_bits_va.fill_with_bits(this->pb, address_bits);
        leaf_digest->generate_r1cs_witness(leaf);
        path_var->generate_r1cs_witness(address, auth_path);
        merkle_check->generate_r1cs_witness();

        root_digest->generate_r1cs_witness(root);
        unpacker->generate_r1cs_witness_from_packed();
    }
};

/*
 * Full identity-attestation gadget
 * Accepts a packed, public input of the form
 * [MERKLE_ROOT, SERIAL_NO, UPPER_BOUNDS, LOWER_BOUNDS, APP_ID||BLOCK_NO||k_BOUND]
 * and an unpacked, auxiliary input of the form
 * [Priv_Key, Merkle_Path, Attributes]
 */

// Strategy:
// Unpack everything into bit strings
// repack into field elements of the correct size

// Todo: Figure out bit-endianness for digests and truncation.
// Consider using knapsack hashes with field-outputs to avoid packing issues. (may cause issues with on-chain issuers)

template<typename FieldT, typename HashT>
class zkid_gadget : gadget<FieldT> {
 private:
  // Must be filled with bits during witness generation
  std::vector<std::shared_ptr<packing_gadget<FieldT>>> bit_packers;

  // split bounds
  std::shared_ptr<multipacking_gadget<FieldT>> upper_splitter;
  std::shared_ptr<multipacking_gadget<FieldT>> lower_splitter;
  std::shared_ptr<multipacking_gadget<FieldT>> attr_splitter;

  std::vector<std::shared_ptr<zkrange_gadget<FieldT>>> range_proofs;

  std::shared_ptr<comparison_gadget<FieldT>> k_compare;

  std::shared_ptr<HashT> serial_hasher;
  std::shared_ptr<HashT> leaf_hasher;

  std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var;
  std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> merkle_check;

 public:
  pb_variable<FieldT> ZERO;

  pb_variable_array<FieldT> upper_bounds_bits;
  pb_variable_array<FieldT> lower_bounds_bits;
  pb_variable_array<FieldT> attributes_split;

  pb_variable<FieldT> k_packed;
  pb_variable<FieldT> k_bound;

  pb_variable_array<FieldT> salt_kbound_bits;
  pb_variable_array<FieldT> k_bits;
  pb_variable_array<FieldT> private_key;

  std::shared_ptr<digest_variable<FieldT>> leaf_digest;
  std::shared_ptr<digest_variable<FieldT>> merkle_root_digest;
  std::shared_ptr<digest_variable<FieldT>> serial_number_digest;

  pb_variable_array<FieldT> address_bits;


  // Public inputs (packed)
  pb_variable<FieldT> merkle_root_packed;
  pb_variable<FieldT> serial_number_packed;
  pb_variable<FieldT> upper_bound_packed;
  pb_variable<FieldT> lower_bound_packed;
  pb_variable<FieldT> salt_kbound_packed;

  // Arrays of individual attribute bounds
  pb_variable_array<FieldT> upper_bounds_split;
  pb_variable_array<FieldT> lower_bounds_split;

  // Hash inputs
  std::shared_ptr<block_variable<FieldT>> serial_inputs;
  std::shared_ptr<block_variable<FieldT>> leaf_inputs;


 zkid_gadget(protoboard<FieldT> &pb, size_t tree_depth, size_t attribute_size) :
  gadget<FieldT>(pb)
   {
      size_t digest_len = HashT::get_digest_len();
      // Note that all hash digests are constrained only up to the size of 1 field element
      // we require a 20-byte address and 4 byte block number, with room left for a k value
      assert(FieldT::capacity() >= 252);

      // Allocate public inputs and designate them as public
      merkle_root_packed.allocate(pb);
      serial_number_packed.allocate(pb);
      upper_bound_packed.allocate(pb);
      lower_bound_packed.allocate(pb);
      salt_kbound_packed.allocate(pb);

      pb.set_input_sizes(5);
      ZERO.allocate(pb);
      private_key.allocate(pb, digest_len);

      leaf_digest.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "leaf"));
      merkle_root_digest.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "root"));
      serial_number_digest.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), "serial"));

      // pack as many attributes as fit into a single field element
      size_t num_attributes = FieldT::capacity()/attribute_size;
      // unpack bounds arrays into single field elements
      upper_bounds_bits.allocate(pb, num_attributes*attribute_size);
      upper_bounds_split.allocate(pb, num_attributes);
      upper_splitter.reset(new multipacking_gadget<FieldT>(pb, upper_bounds_bits, upper_bounds_split, attribute_size));
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, upper_bounds_bits, upper_bound_packed));

      lower_bounds_bits.allocate(pb, num_attributes*attribute_size);
      lower_bounds_split.allocate(pb, num_attributes);
      lower_splitter.reset(new multipacking_gadget<FieldT>(pb, lower_bounds_bits, lower_bounds_split, attribute_size));
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, lower_bounds_bits, lower_bound_packed));

      attributes_split.allocate(pb, num_attributes);

      // constrain each attribute to be in-bounds
      for(int i = 0; i < num_attributes; ++i)
        range_proofs.emplace_back(new zkrange_gadget<FieldT>(pb, attribute_size, upper_bounds_split[i], lower_bounds_split[i], attributes_split[i]));

      // pack salt_bits into salt
      salt_kbound_bits.allocate(pb, digest_len - 8);
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, pb_variable_array<FieldT>(salt_kbound_bits.begin(), salt_kbound_bits.end()-32), salt_kbound_packed));

      // pack k_bound bits into k_bound
      k_bound.allocate(pb);
      pb_variable_array<FieldT> k_bound_bits(salt_kbound_bits.end() - 32, salt_kbound_bits.end());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, k_bound_bits, k_bound));

      // pack k_bits into k_packed
      k_packed.allocate(pb);
      k_bits.allocate(pb, 32);
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, k_bits, k_packed));

      // constrain k_packed to be less than k_bound
      pb_variable<FieldT> lt;
      lt.allocate(pb);
      k_compare.reset(new comparison_gadget<FieldT>(pb, attribute_size, k_packed, k_bound, lt, ONE));

      // construct serial number hash
      pb_variable_array<FieldT> salt_bits(salt_kbound_bits.begin(), salt_kbound_bits.end()-32);
      assert(salt_bits.size() == 27*8);
      serial_inputs.reset(new block_variable<FieldT>(pb, std::vector<pb_variable_array<FieldT>>({private_key, pb_variable_array<FieldT>(8, ZERO), salt_bits, k_bits}), "serial inputs"));
      serial_hasher.reset(new HashT(pb, 512, *serial_inputs, *serial_number_digest, "serial hasher"));

      // pack serial_number low bits
      pb_variable_array<FieldT> serial_low_bits(serial_number_digest->bits.end()-FieldT::capacity(), serial_number_digest->bits.end());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, serial_low_bits,  serial_number_packed));

      // pack merkle_root
      pb_variable_array<FieldT> merkle_low_bits(merkle_root_digest->bits.end()-FieldT::capacity(), merkle_root_digest->bits.end());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, merkle_low_bits, merkle_root_packed));

      // construct merkle root
      pb_variable_array<FieldT> attribute_bits;
      attribute_bits.allocate(pb, 7*attribute_size);;
      attr_splitter.reset(new multipacking_gadget<FieldT>(pb, attribute_bits, attributes_split, attribute_size));
      leaf_inputs.reset(new block_variable<FieldT>(pb,  std::vector<pb_variable_array<FieldT>>({private_key, pb_variable_array<FieldT>(attribute_size, ZERO), attribute_bits}), "leaf inputs"));
      leaf_hasher.reset(new HashT(pb, 512, *leaf_inputs, *leaf_digest, "leaf hasher"));

      address_bits.allocate(pb, tree_depth);
      path_var.reset(new merkle_authentication_path_variable<FieldT, HashT>(pb, tree_depth, "path_var"));
      merkle_check.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(pb, tree_depth, address_bits, *leaf_digest, *merkle_root_digest, *path_var, ONE, ""));
   }

  void generate_r1cs_constraints(){

    generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero());

    for(auto& packer :  bit_packers)
      packer->generate_r1cs_constraints(true);

    upper_splitter->generate_r1cs_constraints(true);
    lower_splitter->generate_r1cs_constraints(true);
    attr_splitter->generate_r1cs_constraints(true);

    for(auto& range : range_proofs)
      range->generate_r1cs_constraints();

    k_compare->generate_r1cs_constraints();

    leaf_hasher->generate_r1cs_constraints();
    serial_hasher->generate_r1cs_constraints();

    path_var->generate_r1cs_constraints();
    merkle_check->generate_r1cs_constraints();

    merkle_root_digest->generate_r1cs_constraints();
    serial_number_digest->generate_r1cs_constraints();
    leaf_digest->generate_r1cs_constraints();
  }

  void generate_r1cs_witness(libff::bit_vector &secret_key,
                             libff::bit_vector &upper_bounds,
                             libff::bit_vector &lower_bounds,
                             libff::bit_vector &attributes,
                             libff::bit_vector &address_bits,
                             libff::bit_vector &salt,
                             const unsigned long k,
                             const unsigned long k_bound,
                             libff::bit_vector merkle_root,
                             size_t &address,
                             std::vector<libsnark::merkle_authentication_node> &auth_path)
  {
    upper_bounds_bits.fill_with_bits(this->pb, upper_bounds);
    lower_bounds_bits.fill_with_bits(this->pb, lower_bounds);
    attr_splitter->bits.fill_with_bits(this->pb, attributes);

    upper_splitter->generate_r1cs_witness_from_bits();
    lower_splitter->generate_r1cs_witness_from_bits();
    attr_splitter->generate_r1cs_witness_from_bits();

    libff::bit_vector k_bound_bits = libff::int_list_to_bits({k_bound}, 32);

    salt.insert(salt.end(), k_bound_bits.end()-32, k_bound_bits.end());
    salt_kbound_bits.fill_with_bits(this->pb, salt);

    k_bits.fill_with_bits(this->pb,  libff::int_list_to_bits({k}, 32));
    private_key.fill_with_bits(this->pb, secret_key);

    merkle_root_digest->generate_r1cs_witness(merkle_root);

    leaf_hasher->generate_r1cs_witness();

    serial_hasher->generate_r1cs_witness();

    this->address_bits.fill_with_bits(this->pb, address_bits);
    path_var->generate_r1cs_witness(address, auth_path);
    merkle_check->generate_r1cs_witness();

    for(auto& packer : bit_packers)
      packer->generate_r1cs_witness_from_bits();

    for(auto& range : range_proofs)
      range->generate_r1cs_witness();

    k_compare->generate_r1cs_witness();

  }
};

#endif
