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
#include "proving/zkidVerificationStructs.h"
#include "proving/zkidMTACircuit.h"
#include "util/libsnark_helpers.h"
#include "util/zkid_helpers.h"
#include "proving/zkidProofGadget.h"
#include "util/json_helpers.h"

using namespace libsnark;

/**
 * zkMTA objects provide verification data for merkle tree authentication proofs on
 * merkle trees of depth [tree_depth].
*/

struct MTAuthenticationNode
{
    bool is_right;
    std::string hash;
    MTAuthenticationNode(const std::string &_hash, bool _is_right) : hash(_hash), is_right(_is_right){};
    MTAuthenticationNode(){};
};

struct ProofRequest {
  std::string secret_key;
  std::string merkle_root;
  std::vector<MTAuthenticationNode> path;

  std::string attributes;
  std::string upper_bounds;
  std::string lower_bounds;
  unsigned long k_bound;
  unsigned long k;
  std::string salt;
};

void ProofRequestFromJson(const std::string &path, ProofRequest &proof);

template <template <typename> typename Hash>
class zkID : public zkidProofGadget
{
  public:
 zkID(int tree_depth, int attribute_size) : _zkid(_pb, tree_depth, attribute_size), attribute_size(attribute_size)
    {
      _zkid.generate_r1cs_constraints();
      auto cs = _pb.get_constraint_system();
      _keypair = std::make_shared<r1cs_ppzksnark_keypair<ppt>>
        (r1cs_ppzksnark_keypair<ppt>(r1cs_ppzksnark_generator<ppt>(cs)));
      _verification_key = r1cs_ppzksnark_verification_key<ppt>(_keypair->vk);
    };

    typedef Hash<FieldT> HashT;

    bool GetVerificationData(ProofRequest &proof_req, VerificationData &data,
                             LibsnarkVerificationData *libsnark_data = nullptr)
    {
        //Pb variables
        const size_t digest_len = HashT::get_digest_len();
        int tree_depth = proof_req.path.size();
        libff::bit_vector address_bits;
        libff::bit_vector root_hash_bv(digest_len);
        libff::bit_vector secret_key_bv(digest_len);
        libff::bit_vector attributes_bv(attribute_size*7);
        libff::bit_vector lower_bounds_bv(attribute_size*7);
        libff::bit_vector upper_bounds_bv(attribute_size*7);
        libff::bit_vector salt_bv(FieldT::capacity()-32);
        std::vector<libsnark::merkle_authentication_node> auth_path(tree_depth);
        size_t address = 0;

        //constructs the authentication path from the provided vector
        this->ConstructPath(tree_depth, proof_req.path, address, address_bits, auth_path);

        //convert root hash string to bit vector
        bit_vector_from_string(root_hash_bv, proof_req.merkle_root);
        bit_vector_from_string(salt_bv, proof_req.salt);
        bit_vector_from_string(secret_key_bv, proof_req.secret_key);
        bit_vector_from_string(attributes_bv, proof_req.attributes);
        bit_vector_from_string(upper_bounds_bv, proof_req.upper_bounds);
        bit_vector_from_string(lower_bounds_bv, proof_req.lower_bounds);

        //Fills in the variables on the protoboard
        _zkid.generate_r1cs_witness(secret_key_bv,
                                    upper_bounds_bv,
                                    lower_bounds_bv,
                                    attributes_bv,
                                    address_bits,
                                    salt_bv,
                                    proof_req.k,
                                    proof_req.k_bound,
                                    root_hash_bv,
                                    address,
                                    auth_path);
        printf("HERE4\n");
        //Generate a authentication proof if the pb is satisified.
        if (!_pb.is_satisfied())
            return false;

        GenerateProof(_pb, data, libsnark_data);

        return true;
    }

    const VerificationError &GetError() const
    {
        return this->_e;
    }

    const r1cs_ppzksnark_verification_key<ppt> &GetVerificationKey()
    {
        return this->_verification_key;
    }

  private:
    void ConstructPath(int tree_depth, const std::vector<MTAuthenticationNode> &path, size_t &address,
                       libff::bit_vector &address_bits, std::vector<merkle_authentication_node> &auth_path)
    {

        for (int cur_depth = tree_depth - 1; cur_depth >= 0; cur_depth--)
        {
            const MTAuthenticationNode node = path[cur_depth];
            const std::string node_hash = node.hash;
            const bool is_right = node.is_right;

            address |= (!is_right ? 1ul << (tree_depth - 1 - cur_depth) : 0);
            address_bits.push_back(!is_right);

            libff::bit_vector cur_node_bv(HashT::get_digest_len());
            bit_vector_from_string(cur_node_bv, node_hash);
            auth_path[cur_depth] = cur_node_bv;
        }
    }

  private:
    int _digest_len = HashT::get_digest_len();
    int attribute_size;
    r1cs_ppzksnark_verification_key<ppt> _verification_key;
    zkid_gadget<FieldT, HashT> _zkid;
    VerificationError _e;
};



void AuthenticationArgsFromJson(const std::string &path_to_json, std::string &leaf, std::string &root,
                                std::vector<MTAuthenticationNode> &path);

template <template <typename> typename Hash>
class zkMTA : public zkidProofGadget
{
  public:
    zkMTA(int tree_depth) : _zkmta(_pb, tree_depth)
    {

        _zkmta.generate_r1cs_constraints();
        _keypair = std::make_shared<r1cs_ppzksnark_keypair<ppt>>
            (r1cs_ppzksnark_keypair<ppt>(r1cs_ppzksnark_generator<ppt>(_pb.get_constraint_system())));
        _verification_key = r1cs_ppzksnark_verification_key<ppt>(_keypair->vk);
    };

    typedef Hash<FieldT> HashT;

    bool GetVerificationData(const std::string &leaf, const std::string &root_hash,
                             const std::vector<MTAuthenticationNode> &path, VerificationData &data,
                             LibsnarkVerificationData *libsnark_data = nullptr)
    {
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
        libff::bit_vector leaf_bv(leaf.length() * 4);
        bit_vector_from_string(leaf_bv, leaf);

        //compute the hash of the leaf's value
        leaf_hash_bv = HashT::get_hash(leaf_bv);

        printf("Leaf: \n");
        std::cout << hex_from_bit_vector(leaf_hash_bv) << std::endl;

        //Fills in the variables on the protoboard
        _zkmta.generate_r1cs_witness(leaf_hash_bv, root_hash_bv, address_bits, address, auth_path);

        //Generate a authentication proof if the pb is satisified.
        if (!_pb.is_satisfied())
            return false;

        GenerateProof(_pb, data, libsnark_data);

        return true;
    }

    const VerificationError &GetError() const
    {
        return this->_e;
    }

    const r1cs_ppzksnark_verification_key<ppt> &GetVerificationKey()
    {
        return this->_verification_key;
    }

  private:
    void ConstructPath(int tree_depth, const std::vector<MTAuthenticationNode> &path, size_t &address,
                       libff::bit_vector &address_bits, std::vector<merkle_authentication_node> &auth_path)
    {

        for (int cur_depth = tree_depth - 1; cur_depth >= 0; cur_depth--)
        {
            const MTAuthenticationNode node = path[cur_depth];
            const std::string node_hash = node.hash;
            const bool is_right = node.is_right;

            address |= (!is_right ? 1ul << (tree_depth - 1 - cur_depth) : 0);
            address_bits.push_back(!is_right);

            libff::bit_vector cur_node_bv(HashT::get_digest_len());
            bit_vector_from_string(cur_node_bv, node_hash);
            auth_path[cur_depth] = cur_node_bv;
        }
    }

  private:
    int _digest_len = HashT::get_digest_len();
    r1cs_ppzksnark_verification_key<ppt> _verification_key;
    zkmta_gadget<FieldT, HashT> _zkmta;
    VerificationError _e;
};

#endif
