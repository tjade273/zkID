#include "network/ZkidRPCServer.h"
#include <cassert>

ZkidRPCServer::ZkidRPCServer(jsonrpc::AbstractServerConnector &conn, ConfigRPCServerInterface *rpc_config) : AbstractZkidRPCServer(conn),
                                                                                                _rpc_config(rpc_config)
{
    
}

Json::Value ZkidRPCServer::GenerateProofs(const Json::Value &credential_descs)
{
    Json::Value result;
    result["success"] = false;

    if (!_proof_handler)
    {
        return result;
    }

    for (int i = 0; i < credential_descs.size(); i++)
    {
        CredentialRequest cred = CredentialRequestFromJson(credential_descs[i]);
        CredentialProof proof;

        if (_proof_handler->GetProofForCredential(cred, proof))
        {
            Json::Value proof_json = ProofToJson(proof);
            proof_json["issuer_address"] = cred.issuer_address;
            result["proofs"].append(proof_json);
        }
    }

    result["success"] = result["proofs"].size() == credential_descs.size();
    return result;
}

CredentialRequest ZkidRPCServer::CredentialRequestFromJson(const Json::Value &cred_json)
{
    CredentialRequest cred_desc;
    cred_desc.issuer_address = cred_json["issuer_address"].asString();
    cred_desc.merkle_root_address = cred_json["merkle_root_address"].asString();
    cred_desc.range_low = cred_json["range_low"].asInt();
    cred_desc.range_high = cred_json["range_high"].asInt();
    cred_desc.k_factor = cred_json["k_factor"].asInt();

    return cred_desc;
}

Json::Value ZkidRPCServer::ProofToJson(const CredentialProof &proof)
{
    Json::Value proof_json;
    proof_json["A"][0] = proof.A[0];
    proof_json["A"][1] = proof.A[1];
    proof_json["A_p"][0] = proof.A_p[0];
    proof_json["A_p"][1] = proof.A_p[1];
    proof_json["B"][0] = proof.B[0];
    proof_json["B"][1] = proof.B[1];
    proof_json["B"][2] = proof.B[2];
    proof_json["B"][3] = proof.B[3];
    proof_json["B_p"][0] = proof.B_p[0];
    proof_json["B_p"][1] = proof.B_p[1];
    proof_json["C"][0] = proof.C[0];
    proof_json["C"][1] = proof.C[1];
    proof_json["C_p"][0] = proof.C_p[0];
    proof_json["C_p"][1] = proof.C_p[1];
    proof_json["H"][0] = proof.H[0];
    proof_json["H"][1] = proof.H[1];
    proof_json["K"][0] = proof.K[0];
    proof_json["K"][1] = proof.K[1];

    return proof_json;
}

void ZkidRPCServer::SetProofHandler(ZkidProofHandler *handler)
{
    this->_proof_handler = handler;
}