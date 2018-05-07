#include "network/ZkidRPCServer.h"

Json::Value ZkidRPCServer::GenerateProofs(const Json::Value &credential_descriptions)
{
    zkidProver prover(_rpc_config);

    Json::Value result;
    result["success"] = false;

    for (int i = 0; i < credential_descriptions.size(); i++)
    {
        Json::Value cur = credential_descriptions[i];
        const std::string issuer_address = cur["issuer_address"].asString();
        if (!_cred_manager->HasCredential(issuer_address))
        {
            return result;
        }

        const std::string credential = _cred_manager->GetCredential(issuer_address);

        VerificationProof proof;
        if (!prover.GenerateProof(credential, issuer_address, cur["range_low"].asString(), cur["range_high"].asString(), cur["k_factor"].asString(), proof))
        {
            return result;
        }

        Json::Value proof_json = ProofToJson(proof);

        result["proofs"].append(proof_json);
    }

    result["success"] = true;
    return result;
};

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
    proof_json["B_p"][1] = Json::Value(proof.B_p[0]);
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