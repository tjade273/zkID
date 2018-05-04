#ifndef _zkMTACircuit_h
#define _zkMTACircuit_h

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using namespace libsnark;

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
        root_digest->generate_r1cs_witness(root);
        path_var->generate_r1cs_witness(address, auth_path);
        merkle_check->generate_r1cs_witness();
        unpacker->generate_r1cs_witness_from_packed();
    }
};

#endif
