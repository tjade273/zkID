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
            unpacked_inputs.emplace_back();
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
        root_digest->generate_r1cs_witness(root);
        path_var->generate_r1cs_witness(address, auth_path);
        merkle_check->generate_r1cs_witness();
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
  // unpacked field elements
  pb_variable_array<FieldT> root_bits;
  pb_variable_array<FieldT> serial_bits;
  pb_variable_array<FieldT> upper_bits;
  pb_variable_array<FieldT> lower_bits;
  pb_variable_array<FieldT> attribute_bits;
  pb_variable_array<FieldT> address_bits_va;
  digest_variable<FieldT> leaf_digest;

  std::vector<std::shared_ptr<packing_gadget>> unpackers;

  // split bounds
  std::shared_ptr<multipacking_gadget<FieldT>> upper_splitter;
  std::shared_ptr<multipacking_gadget<FieldT>> lower_splitter;
  std::shared_ptr<multipacking_gadget<FieldT>> attr_splitter;

  std::vector<std::shared_ptr<zkrange_gadget>> range_proofs;

  std::shared_ptr<HashT> serial_hasher;
  std::shared_ptr<HashT> leaf_hasher;

  std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var;
  std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> merkle_check;

 public:
  digest_variable<FieldT> merkle_root;
  digest_variable<FieldT> serial_number;
  pb_variable_array<FieldT> upper_bound;
  pb_variable_array<FieldT> lower_bounds;
  pb_variable_array<FieldT> attributes;
  digest_variable<FieldT> attribute_bits;
  digest_variable<FieldT> salt_bits;
  digest_variable<FieldT> private_key;

 zkid_gadget(protoboard<FieldT> &pb,
             pb_variable<FieldT> &merkle,
             pb_variable<FieldT> &serial,
             pb_variable<FieldT> &upper,
             pb_variable<FieldT> &lower,
             pb_variable<FieldT> &salt,
             size_t tree_depth,
             size_t attribute_size) :
  gadget<FieldT>(pb),
    merkle_root(pb, HashT::get_digest_len()),
    serial_number(pb, HashT::get_digest_len()),
    private_key(pb, HashT::get_digest_len()),
    salt_bits(pb, HashT::get_digest_len()),
    leaf_digest(pb, HashT::get_digest_len()),
    attribute_bits(pb, HashT::get_digest_len())
    {
      // Note that all hash digests are constrained only up to the size of 1 field element

      // we require a 20-byte address and 4 byte block number, with room left for a k value
      assert(FieldT::capacity() >= 252);

      // pack as many attributes as fit into a single field element
      size_t num_attributes = FieldT::capacity()/attribute_size;

      // constrain bit-representations to equal the packed field representations
      upper_bits.allocate(pb, num_attributes*attribute_size);
      lower_bits.allocate(pb, num_attributes*attribute_size);

      unpackers.emplace_back(new packing_gadget<FieldT>(pb, upper_bits, upper));
      unpackers.emplace_back(new packing_gadget<FieldT>(pb, lower_bits, lower));
      unpackers.emplace_back(new packing_gadget<FieldT>(pb, root_bits, merkle_root));
      unpackers.emplace_back(new packing_gadget<FieldT>(pb, serial_bits, serial_number));

      // constrain split representation to be equivalent to bit representation
      attributes.allocate(pb, num_attributes);
      upper_bounds.allocate(pb, num_attributes);
      lower_bounds.allocate(pb, num_attributes);

      upper_splitter.reset(new multipacking_gadget<FieldT>(pb, upper_bits, upper_bounds, attribute_size));
      lower_splitter.reset(new multipacking_gadget<FieldT>(pb, lower_bits, lower_bounds, attribute_size));
      pb_variable_array<FieldT> attr_bottom_bits(attribute_bits.bits.begin(), attribute_bits.bits.begin() + num_attributes*attribute_size);
      attr_splitter.reset(new multipacking_gadget<FieldT>(pb, attribute_bits.bits., attributes, attribute_size));

      // constrain each attribute to be in-bounds
      for(int i = 0; i < num_attributes; ++i)
        range_proofs.emplace_back(pb, attribute_size, upper_bounds[i], lower_bounds[i], attributes[i]);

      // Allocate space for a private key

      size_t digest_size = HashT::get_digest_len();

      // constrain serial number to equal bottom FieldT::capacity() bits of the digest
      pb_variable_array<FieldT> serial_bottom_bits(serial_number.bits.begin(), serial_number.bits.begin()+FieldT::capacity());
      unpackers.emplace_back(new packing_gadget<FieldT>(pb, serial_bottom_bits, serial));

      // constrain serial number to be H(privkey, salt)
      serial_hasher.reset(HashT(pb, private_key, salt_bits, serial_number));

      // constrain H(privkey, attributes) to be leaf of merkle tree
      pb_variable_array<FieldT> merkle_bottom_bits(merkle_root.bits.begin(), merkle_root.bits.begin()+FieldT::capacity());
      unpackers.emplace_back(new packing_gadget<FieldT>(pb, merkle_bottom_bits, merkle));
      leaf_hasher.reset(HashT(pb, private_key, attribute_bits, leaf_digest));
      address_bits_va.allocate(pb, tree_depth);
      merkle_check.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(pb, tree_depth, address_bits_va, leaf_digest, merkle_root, path, ONE));

      // constrain salt to have k less than k_bound
      //TODO
};

#endif
