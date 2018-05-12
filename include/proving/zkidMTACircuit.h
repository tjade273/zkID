#ifndef _zkMTACircuit_h
#define _zkMTACircuit_h

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

//TODO remove:
#include "util/libsnark_helpers.h"


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
                   pb_linear_combination<FieldT> &upper_bound,
                   pb_linear_combination<FieldT> &lower_bound,
                   pb_linear_combination<FieldT> &attribute)
        : gadget<FieldT>(pb), attribute(attribute)
        {
            // Generate dummy variables for LT, we only care about LE
            // we won't further constrain lt1, lt2 so we can simply discard them after allocation.
            pb_variable<FieldT> lt1, lt2;
            lt1.allocate(pb);
            lt2.allocate(pb);

            // Constrain `attribute <= upper_bound`
            upper.reset(new comparison_gadget<FieldT>(n, attribute, upper_bound, lt1, ONE));

            //Constrain `lower_bound <= attribute`
            lower.reset(new comparison_gadget<FieldT>(n, lower_bound, lt2, ONE));
        }
    void generate_r1cs_constraints(){
        upper->generate_r1cs_constraints();
        lower->generate_r1cs_constraints();
    }
    void generate_r1cs_witness(){
        upper->generate_r1cs_witnwss();
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
        printf("Merkle root:\n");
        std::cout << hex_from_bit_vector(merkle_check->root.get_digest()) << std::endl;

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
  pb_variable_array<FieldT> upper_bounds_bits;
  pb_variable_array<FieldT> lower_bounds_bits;
  pb_variable_array<FieldT> attributes_split;

  pb_variable<FieldT> k_packed;
  pb_variable<FieldT> k_bound;

  pb_variable_array<FieldT> salt_kbound_bits;
  pb_variable_array<FieldT> k_bits;
  pb_variable_array<FieldT> private_key;

  digest_variable<FieldT> leaf_digest;
  digest_variable<FieldT> merkle_root_digest;
  digest_variable<FieldT> serial_number_digest;

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
  block_variable<FieldT> serial_inputs;
  block_variable<FieldT> leaf_inputs;


 zkid_gadget(protoboard<FieldT> &pb,
             size_t tree_depth,
             size_t attribute_size) :
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

      private_key.allocate(pb, digest_len);

      // pack as many attributes as fit into a single field element
      size_t num_attributes = FieldT::capacity()/attribute_size;

      // unpack bounds arrays into single field elements
      upper_bounds_bits.allocate(pb, num_attributes*attribute_size);
      upper_bounds_split.allocate(pb, num_attributes);
      upper_splitter.reset(new multipacking_gadget<FieldT>(pb, upper_bounds_bits, upper_bounds_split, attribute_size));
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, upper_bound_packed, upper_bounds_bits));

      lower_bounds_bits.allocate(pb, num_attributes*attribute_size);
      lower_bounds_split.allocate(pb, num_attributes);
      lower_splitter.reset(new multipacking_gadget<FieldT>(pb, lower_bounds_bits, lower_bounds_split, attribute_size));
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, lower_bound_packed, lower_bounds_bits));

      // constrain each attribute to be in-bounds
      for(int i = 0; i < num_attributes; ++i)
        range_proofs.emplace_back(pb, attribute_size, upper_bounds_split[i], lower_bounds_split[i], attributes_split[i]);

      // pack salt_bits into salt
      salt_kbound_bits.allocate(pb, FieldT::capacity());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, salt_kbound_packed, salt_kbound_bits));

      // pack k_bound bits into k_bound
      pb_variable_array<FieldT> k_bound_bits(salt_kbound_bits.end() - 32, salt_kbound_bits.end);
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, k_bound, k_bound_bits));

      // pack k_bits into k_packed
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, k_packed, k_bits));

      // constrain k_packed to be less than k_bound
      pb_variable<FieldT> lt;
      pb.allocate(lt);
      k_compare.reset(new comparison_gadget<FieldT>(pb, attribute_size, k_packed, k_bound, lt, ONE));

      // construct serial number hash
      pb_variable_array<FieldT> salt_bits(salt_kbound_bits.begin(), salt_kbound_bits.end()-32);
      serial_number_digest = digest_variable<FieldT>(pb, digest_len);
      serial_inputs = block_variable<FieldT>({private_key, salt_bits, k_bits});
      serial_hasher.reset(HashT(pb, serial_inputs, serial_number_digest));

      // pack serial_number low bits
      pb_variable_array<FieldT> serial_low_bits(serial_number_digest.bits.end()-FieldT::capacity(), serial_number_digest.bits.end());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, serial_number_packed, serial_low_bits));

      // pack merkle_root
      merkle_root_digest = digest_variable<FieldT>(pb, digest_len);
      pb_variable_array<FieldT> merkle_low_bits(merkle_root_digest.bits.end()-FieldT::capacity(), merkle_root_digest.bits.end());
      bit_packers.emplace_back(new packing_gadget<FieldT>(pb, merkle_root_packed, merkle_low_bits));

      // construct merkle root
      pb_variable_array<FieldT> attribute_bits;
      attribute_bits.allocate(digest_len);
      attr_splitter.reset(new multipacking_gadget<FieldT>(pb, attribute_bits, attributes_split, attribute_size));
      leaf_inputs = block_variable<FieldT>({private_key, attribute_bits});
      leaf_digest = digest_variable<FieldT>(pb, digest_len);
      leaf_hasher.reset(HashT(pb, leaf_inputs, leaf_digest));

      address_bits.allocate(pb, tree_depth);
      path_var.reset(new merkle_authentication_path_variable<FieldT, HashT>(pb, tree_depth, "path_var"));
      merkle_check.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(pb, tree_depth, address_bits, leaf_digest, merkle_root_digest, path_var, ONE));
    }

  void generate_r1cs_constraints(){
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

    leaf_inputs->generate_r1cs_constraints();
    serial_inputs->generate_r1cs_constraints();
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
                             libff::bit_vector &addr_bits,
                             size_t &address,
                             std::vector<libsnark::merkle_authentication_node> &auth_path)
  {
    upper_bounds_bits.fill_with_bits(this->pb, upper_bounds);
    lower_bounds_bits.fill_with_bits(this->pb, lower_bounds);
    attr_splitter->bits.fill_with_bits(this->pb, attributes);

    upper_splitter->generate_r1cs_witness_from_bits();
    lower_splitter->generate_r1cs_witness_from_bits();
    attr_splitter->generate_r1cs_witness_from_bits();

    // true means unsigned
    this->pb.val(k_packed) = FieldT(k, true);
    this->pb.val(k_bound) = FieldT(k_bound, true);

    k_compare->generate_r1cs_witness();

    libff::bit_vector k_bound_bits = libff::convert_field_element_to_bit_vector(k_bound);
    salt.insert(salt.end(), k_bound_bits.begin(), k_bound_bits.end());
    salt_kbound_bits.fill_with_bits(this->pb, salt);
    k_bits.fill_with_bits_of_ulong(this->pb, k);
    private_key.fill_with_bits(this->pb, secret_key);

    merkle_root_digest.generate_r1cs_witness(merkle_root);
    attributes.insert(attributes.begin(), secret_key.begin(), secret_key.end());
    leaf_digest.generate_r1cs_witness(HashT::get_hash(attributes));

    libff::bit_vector serial_leaf;
    serial_leaf.insert(serial_leaf.end(), secret_key.begin(), secret_key.end());
    serial_leaf.insert(serial_leaf.end(), salt.begin(), salt.end() - k_bound_bits.size());
    auto k_bv = k_bits.get_bits(this->pb);
    serial_leaf.insert(serial_leaf.end(), k_bv.begin(), k_bv.end());
    serial_number_digest.generate_r1cs_witness(HashT::get_hash(serial_leaf));

    this->address_bits.fill_with_bits(this->pb, addr_bits);

    path_var->generate_r1cs_witness(address, auth_path);
    merkle_check->generate_r1cs_witness();
  }
};

#endif
