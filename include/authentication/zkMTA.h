#ifndef _zkMTA_h
#define _zkMTA_h

#include <fstream>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include "authentication/zkMTAStructs.h"
#include "authentication/zkMTACircuit.h"
#include "util/libsnark_helpers.h"
#include "util/zk_identity_helpers.h"

using namespace libsnark;

struct LibsnarkAuthenticationData{
    r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> pvk;
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;
    r1cs_ppzksnark_primary_input<libff::alt_bn128_pp> primary_input;
};


template <template <typename> typename Hash>
class zkMTA
{
  public:
    zkMTA(){};

    typedef libff::alt_bn128_pp ppt;
    typedef libff::Fr<ppt> FieldT;
    typedef Hash<FieldT> HashT;

    bool Authenticate(const std::string &leaf, const std::string &root_hash,
                      const std::vector<AuthenticationNode> &path, AuthenticationData &data,
                      LibsnarkAuthenticationData* libsnark_data = nullptr)
    {
        ppt::init_public_params();

        //Pb variables
        const size_t digest_len = HashT::get_digest_len();
        int tree_depth = path.size();
        libff::bit_vector address_bits;
        libff::bit_vector leaf_hash_bv(digest_len);
        libff::bit_vector root_hash_bv(digest_len);
        std::vector<libsnark::merkle_authentication_node> auth_path(tree_depth);
        size_t address = 0;

        //constructs the authentication path from the provided vector
        this->ConstructPath(tree_depth, path, address, address_bits, auth_path);

        //convert root hash string to bit vector
        bit_vector_from_string(root_hash_bv, root_hash);

        //convert leaf value to bit vector
        libff::bit_vector leaf_bv(leaf.length()*4);
        bit_vector_from_string(leaf_bv,leaf);

        //TODO: This assumes that the provided leaf does not exceed HashT's block size.

        //compute the hash of the leaf's value
        leaf_hash_bv = HashT::get_hash(leaf_bv);

        //Fills in the variables on the protoboard
        protoboard<FieldT> pb;
        this->FillPb(pb,leaf_hash_bv,root_hash_bv, address_bits,address,auth_path);

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

        zkmta_gadget<FieldT, HashT> zkmta(pb, tree_depth);
        zkmta.generate_r1cs_constraints();
        zkmta.generate_r1cs_witness(leaf, root, address_bits, address, auth_path);
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
