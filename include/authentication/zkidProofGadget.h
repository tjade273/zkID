#ifndef _zkid_Proof_Gadget_h
#define _zkid_Proof_Gadget_h

#include "zkidVerificationStructs.h"
#include "util/zk_identity_helpers.h"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

class zkidProofGadget
{
  public:
    typedef libff::alt_bn128_pp ppt;
    typedef libff::Fr<ppt> FieldT;
    zkidProofGadget() : _pb() {}
    virtual void GenerateProof(protoboard<FieldT> &pb, 
        VerificationData &v_data, LibsnarkVerificationData *libsnark_data = nullptr)
    {
        r1cs_ppzksnark_proof<ppt> proof = r1cs_ppzksnark_prover<ppt>(_keypair->pk, _pb.primary_input(), _pb.auxiliary_input());

        if (libsnark_data)
        {
            libsnark_data->proof = proof;
            libsnark_data->primary_input = _pb.primary_input();
        }

        v_data.proof = ExtractVerificationProof(proof);
    }

  protected:
    protoboard<FieldT> _pb;
    std::shared_ptr<r1cs_ppzksnark_keypair<ppt>> _keypair; 

};
#endif