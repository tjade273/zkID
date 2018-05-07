#include "network/ZkidRPCServer.h"

Json::Value ZkidRPCServer::GenerateProofs(const Json::Value &params)
{
    Json::Value credential_descs = params["credential_descriptions"];
    Json::Value result;
    result["success"] = false;

    if (!_proof_handler)
    {
        return result;
    }

    for (int i = 0; i < credential_descs.size(); i++)
    {
        CredentialDescription cred = CredentialDescriptionFromJson(credential_descs[i]);
        VerificationProof proof;

        if (_proof_handler->GetProofForCredential(cred, proof))
        {
            result["proofs"].append(ProofToJson(proof));
        }
    }

    result["success"] = true;
    return result;
}

CredentialDescription ZkidRPCServer::CredentialDescriptionFromJson(const Json::Value &cred_json)
{
    CredentialDescription cred_desc;
    cred_desc.issuer_address = cred_json["issuer_address"].asString();
    cred_desc.range_low = cred_json["range_low"].asString();
    cred_desc.range_high = cred_json["range_high"].asString();
    cred_desc.k_factor = cred_json["k_factor"].asString();

    return cred_desc;
}

Json::Value ZkidRPCServer::ProofToJson(const VerificationProof &proof)
{
    Json::Value proof_json;
    proof_json["A"][0] = Json::Value(proof.A[0]);
    proof_json["A"][1] = Json::Value(proof.A[1]);
    proof_json["A_p"][0] = Json::Value(proof.A_p[0]);
    proof_json["A_p"][1] = Json::Value(proof.A_p[1]);
    proof_json["B"][0] = Json::Value(proof.B[0]);
    proof_json["B"][1] = Json::Value(proof.B[1]);
    proof_json["B"][2] = Json::Value(proof.B[2]);
    proof_json["B"][3] = Json::Value(proof.B[3]);
    proof_json["B_p"][0] = Json::Value(proof.B_p[0]);
    proof_json["B_p"][1] = Json::Value(proof.B_p[1]);
    proof_json["C"][0] = Json::Value(proof.C[0]);
    proof_json["C"][1] = Json::Value(proof.C[1]);
    proof_json["C_p"][0] = Json::Value(proof.C_p[0]);
    proof_json["C_p"][1] = Json::Value(proof.C_p[1]);
    proof_json["H"][0] = Json::Value(proof.H[0]);
    proof_json["H"][1] = Json::Value(proof.H[1]);
    proof_json["K"][0] = Json::Value(proof.K[0]);
    proof_json["K"][1] = Json::Value(proof.K[1]);

    return proof_json;
}