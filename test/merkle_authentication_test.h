#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include "json.hpp"
#include <fstream>

using namespace libsnark;
using json = nlohmann::json;

void bit_vector_from_string(libff::bit_vector& vect, const std::string& s){
    for(int i = 0; i < s.size(); i+=2){
        unsigned int v;
        std::string hex_char = s.substr(i,2);
        std::stringstream ss;
        ss << hex_char;
        ss >> std::hex >> v;
        for(int j = 7; j >= 0; j--){
            vect[i*4 + (7-j)] = v & (1 << j); 
        }
    }
}


TEST(MerkleAutenticationTest, TestBitVectorFromString){
    libff::bit_vector hash_string_bv(SHA256_digest_size);
    bit_vector_from_string(hash_string_bv,"038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");

    const libff::bit_vector int_list_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);

    ASSERT_TRUE(int_list_bv.size() == hash_string_bv.size());
    for(int i = 0; i < hash_string_bv.size(); i++){
        ASSERT_TRUE(hash_string_bv[i] == int_list_bv[i]);
    }

}

TEST(MerkleAutenticationTest, TestValidWitness) {
    libff::start_profiling();

   /* prepare test */
    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;
    const size_t digest_len = HashT::get_digest_len();
    const size_t tree_depth = 3;
    libff::bit_vector address_bits;
    size_t address = 0; //represents the address_bits vector as a number

    libff::bit_vector root(digest_len);
    libff::bit_vector leaf(digest_len);
    std::vector<merkle_authentication_node> path(tree_depth);

    //read in test file;
    std::ifstream f("res/merkle_path_test_pass.json");

    if (!f) std::cout << "Failed to open file stream" << std::endl;

    json j;
    f >> j;

    const std::string root_hash = j["root"];
    const std::string leaf_hash = j["leaf"];
    json path_hashes = j["path"];

    //convert root & leaf hashes into bit_vectors
    bit_vector_from_string(root,root_hash);
    bit_vector_from_string(leaf,leaf_hash);

    //construct authentication path
    json::iterator cur_node_it = path_hashes.begin();
    for(int cur_depth = tree_depth-1; cur_depth >= 0; ++cur_node_it, --cur_depth){
        const std::string node_hash = (*cur_node_it)["hash"];
        const bool is_right = !(*cur_node_it)["right"];

        address |= (is_right ? 1ul << (tree_depth-1-cur_depth) : 0);
        address_bits.push_back(is_right);

        libff::bit_vector cur_node_bv(digest_len);
        bit_vector_from_string(cur_node_bv,node_hash);
        path[cur_depth] = cur_node_bv;
    }

    //Do test
    protoboard<FieldT> pb;
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, 
                        leaf_digest, root_digest, path_var, ONE, "ml");

    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    address_bits_va.fill_with_bits(pb, address_bits);
    
    ASSERT_TRUE(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);
    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();

    /* make sure that read checker didn't accidentally overwrite anything*/
    address_bits_va.fill_with_bits(pb, address_bits);
    leaf_digest.generate_r1cs_witness(leaf);
    root_digest.generate_r1cs_witness(root);
    ASSERT_TRUE(pb.is_satisfied());

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    ASSERT_TRUE(num_constraints == expected_constraints);
}