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
#include "proving/zkidCircuit.h"
#include "util/libsnark_helpers.h"
#include "util/zkid_helpers.h"
#include "proving/zkidProofGadget.h"
#include "util/json_helpers.h"
#include "proving/zkidProver.h"

using namespace libsnark;

/**
 * zkMTA objects provide verification data for merkle tree authentication proofs on
 * merkle trees of depth [tree_depth].
*/

void ProofRequestFromJson(const std::string &path, ProofRequest &proof);

template <template <typename> typename Hash>
class zkidProverImpl : public zkidProofGadget, public zkidProver
{
  public:
 zkidProverImpl(int tree_depth, int attr_size) : _zkid(_pb, tree_depth, attr_size), attribute_size(attr_size)
    {
      _zkid.generate_r1cs_constraints();
      GenerateKeys();
    };

 zkidProverImpl(int tree_depth, int attr_size,  std::string key_path) : _zkid(_pb, tree_depth, attr_size), attribute_size(attr_size)
  {
    _zkid.generate_r1cs_constraints();
    ImportKeys(key_path);
  };

  typedef Hash<FieldT> HashT;

    void GenerateKeys(){
      _keypair = std::make_shared<r1cs_ppzksnark_keypair<ppt>>
        (r1cs_ppzksnark_keypair<ppt>(r1cs_ppzksnark_generator<ppt>(_pb.get_constraint_system())));
    }

    void ExportKeys(std::string f){
      std::ofstream vk_file(f + "/verifier.key");
      std::ofstream pk_file(f + "/prover.key");
      if(!vk_file || !pk_file)
        std::cout << "File not found" << std::endl;

      vk_file << _keypair->vk;
      pk_file << _keypair->pk;
      vk_file.close();
      pk_file.close();
    }

    void ImportKeys(std::string f){
      std::ifstream vk_file(f + "/verifier.key");
      std::ifstream pk_file(f + "/prover.key");

      if(!vk_file || !pk_file)
        std::cout << "File not found" << std::endl;

      r1cs_ppzksnark_verification_key<ppt> vk;
      r1cs_ppzksnark_proving_key<ppt> pk;
      vk_file >> vk;
      pk_file >> pk;

      vk_file.close();
      pk_file.close();
      _keypair.reset(new r1cs_ppzksnark_keypair<ppt>(std::move(pk), std::move(vk)));
    }

    bool GetCredentialProof(ProofRequest &proof_req, CredentialProof &data,
                             LibsnarkCredentialProof *libsnark_data = nullptr)
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
        libff::bit_vector salt_bv(digest_len - 40);
        std::vector<libsnark::merkle_authentication_node> auth_path(tree_depth);
        size_t address = 0;

        this->ConstructPath(tree_depth, proof_req.path, auth_path);

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

        pb_variable_array<FieldT> k_bound_bits(_zkid.salt_kbound_bits.end() - 32, _zkid.salt_kbound_bits.end());

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
      return r1cs_ppzksnark_verification_key<ppt>(_keypair->vk);
    }

    const r1cs_ppzksnark_proving_key<ppt> &GetProvingKey(){
      return r1cs_ppzksnark_proving_key<ppt>(_keypair->pk);
    }

  private:
    void ConstructPath(int tree_depth, const std::vector<std::string> &path, std::vector<merkle_authentication_node> &auth_path)
    {
        for (int cur_depth = tree_depth - 1; cur_depth >= 0; cur_depth--)
        {
            libff::bit_vector cur_node_bv(HashT::get_digest_len());
            bit_vector_from_string(cur_node_bv, path[cur_depth]);
            auth_path[cur_depth] = cur_node_bv;
        }
    }

  private:
    int _digest_len = HashT::get_digest_len();
    int attribute_size;
    
    zkid_gadget<FieldT, HashT> _zkid;
    VerificationError _e;
};
#endif
