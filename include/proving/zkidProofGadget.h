#ifndef _zkid_Proof_Gadget_h
#define _zkid_Proof_Gadget_h

#include "zkidVerificationStructs.h"
#include "util/zkid_helpers.h"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

class zkidProofGadget
{
  public:
    typedef libff::alt_bn128_pp ppt;
    typedef libff::Fr<ppt> FieldT;
    zkidProofGadget() : _pb() {}
    virtual void GenerateProof(protoboard<FieldT> &pb,
        CredentialProof &cred_proof, LibsnarkCredentialProof &libsnark_data)
    {
        r1cs_ppzksnark_proof<ppt> proof = r1cs_ppzksnark_prover<ppt>(_keypair->pk, _pb.primary_input(), _pb.auxiliary_input());

        libsnark_data.proof = proof;
        libsnark_data.primary_input = _pb.primary_input();

        cred_proof.serial = HexStringFromLibsnarkBigint(libsnark_data.primary_input[1].as_bigint());
        ExtractCredentialProof(proof, cred_proof);
    }

  protected:
    protoboard<FieldT> _pb;
    std::shared_ptr<r1cs_ppzksnark_keypair<ppt>> _keypair;

};
#endif
