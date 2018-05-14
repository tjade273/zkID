#ifndef _zkidProver_h
#define _zkidProver_h

#include "zkidVerificationStructs.h"
#include "util/zkid_helpers.h"

struct ProofRequest {
  std::string secret_key;
  std::string merkle_root;
  std::vector<std::string> path;
  size_t address;
  std::string attributes;
  std::string upper_bounds;
  std::string lower_bounds;
  unsigned long k_bound;
  unsigned long k;
  std::string salt;
};


class zkidProver{
    public:
         virtual bool GetCredentialProof(ProofRequest &proof_req, CredentialProof &data,
                             LibsnarkCredentialProof &libsnark_data) = 0;
};
#endif
