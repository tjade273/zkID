#ifndef _zkMerkleTreeAuthenticator_h
#define _zkMerkleTreeAuthenticator_h

#include <fstream>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include "util/libsnark_helpers.h"
#include "src/authentication/zkMerkleTreeAuthenticationStructs.h"
#include "util/zk_identity_helpers.h"

using namespace libsnark;

struct LibsnarkAuthenticationData{
    r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> pvk;
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;
    r1cs_ppzksnark_primary_input<libff::alt_bn128_pp> primary_input;
};


template <template <typename> typename Hash>
class zkMerkleTreeAuthenticator
{
  public:
    zkMerkleTreeAuthenticator(){};

    typedef libff::alt_bn128_pp ppt;
    typedef libff::Fr<ppt> FieldT;
    typedef Hash<FieldT> HashT;

    bool Authenticate(const std::string &leaf_hash, const std::string &root_hash,
                      const std::vector<AuthenticationNode> &path, AuthenticationData &data,
                      LibsnarkAuthenticationData* libsnark_data = nullptr)
    {
        ppt::init_public_params();

        //Pb variables
        const size_t digest_len = HashT::get_digest_len();
        int tree_depth = path.size();
        libff::bit_vector address_bits;
        libff::bit_vector leaf(digest_len);
        libff::bit_vector root(digest_len);
        std::vector<libsnark::merkle_authentication_node> auth_path(tree_depth);
        size_t address = 0;

        //constructs a the authentication path from the provided vector
        this->ConstructPath(tree_depth, path, address, address_bits, auth_path);
        bit_vector_from_string(root, root_hash);
        bit_vector_from_string(leaf, leaf_hash);

        //Fills in the variables on the protoboard
        protoboard<FieldT> pb;
        this->FillPb(pb,leaf,root,address_bits,address,auth_path);

        //Genreate a authentication proof if the pb is satisified.
        
        return this->GenerateAuthenticationData(pb, data,libsnark_data);
    }

    AuthenticationError GetError() const
    {
        return this->_e;
    }


    bool GenerateAuthenticationData(protoboard<FieldT> &pb, AuthenticationData &auth_data, LibsnarkAuthenticationData* libsnark_data = nullptr)
    {
        if(!pb.is_satisfied())
            return false;

        r1cs_ppzksnark_keypair<ppt> keypair = r1cs_ppzksnark_generator<ppt>(pb.get_constraint_system());
        r1cs_ppzksnark_verification_key<ppt> pvk = r1cs_ppzksnark_verification_key<ppt>(keypair.vk);
        r1cs_ppzksnark_proof<ppt> proof = r1cs_ppzksnark_prover<ppt>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
        
        if(libsnark_data){
            libsnark_data->pvk = pvk;
            libsnark_data->proof = proof;
            libsnark_data->primary_input = pb.primary_input();
        }

        auth_data.proof = ExtractAuthenticationProof(proof);
        auth_data.key = ExtractVerificationKey(pvk);

        return true;
    }

  private:
    int _digest_len = HashT::get_digest_len();

    void FillPb(protoboard<FieldT> &pb, libff::bit_vector &leaf, libff::bit_vector &root,
                libff::bit_vector& address_bits, size_t &address, std::vector<libsnark::merkle_authentication_node> &auth_path)
    {
        int tree_depth = auth_path.size();
        pb_variable_array<FieldT> address_bits_va;
        address_bits_va.allocate(pb, auth_path.size(), "address_bits");
        digest_variable<FieldT> leaf_digest(pb, _digest_len, "input_block");
        digest_variable<FieldT> root_digest(pb, _digest_len, "output_digest");
        merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
        merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va,
                                                        leaf_digest, root_digest, path_var, ONE, "ml");

        path_var.generate_r1cs_constraints();
        ml.generate_r1cs_constraints();

        address_bits_va.fill_with_bits(pb, address_bits);

        leaf_digest.generate_r1cs_witness(leaf);
        path_var.generate_r1cs_witness(address, auth_path);
        ml.generate_r1cs_witness();

        address_bits_va.fill_with_bits(pb, address_bits);
        leaf_digest.generate_r1cs_witness(leaf);
        root_digest.generate_r1cs_witness(root);
    }

    void ConstructPath(int tree_depth, const std::vector<AuthenticationNode> &path, size_t &address,
                       libff::bit_vector &address_bits, std::vector<merkle_authentication_node> &auth_path)
    {

        for (int cur_depth = tree_depth - 1; cur_depth >= 0; cur_depth--)
        {
            const AuthenticationNode node = path[cur_depth];
            const std::string node_hash = node.hash;
            const bool is_right = node.is_right;

            address |= (!is_right ? 1ul << (tree_depth - 1 - cur_depth) : 0);
            address_bits.push_back(!is_right);

            libff::bit_vector cur_node_bv(HashT::get_digest_len());
            bit_vector_from_string(cur_node_bv, node_hash);
            auth_path[cur_depth] = cur_node_bv;
        }
    }
    AuthenticationError _e;
};

#endif