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
            proof_json["contract_salt"] = cred.contract_salt;
            result["proofs"].append(proof_json);
        }
    }

    result["success"] = result["proofs"].size() == credential_descs.size();
    return result;
}

CredentialRequest ZkidRPCServer::CredentialRequestFromJson(const Json::Value &cred_json)
{
    CredentialRequest cred_desc;
    cred_desc.contract_salt = cred_json["contract_salt"].asString();
    cred_desc.merkle_root_address = cred_json["merkle_root_address"].asString();
    cred_desc.k_bound = cred_json["k_bound"].asInt();

    for (const Json::Value &attr_req_json : cred_json["requested_attributes"])
    {
        AttributeRequest attr_request;
        attr_request.lower_bound = attr_req_json["lower_bound"].asString();
        attr_request.upper_bound = attr_req_json["upper_bound"].asString();
        attr_request.idx = attr_req_json["idx"].asInt();
        cred_desc.attribute_requests.push_back(attr_request);
    }
    
    if (cred_desc.attribute_requests.size() < ZKID_CREDENTIAL_ATTRIBUTE_NUM)
    {
        for (int i = 0; i < ZKID_CREDENTIAL_ATTRIBUTE_NUM; i++)
        {
            if(cred_desc.attribute_requests.size() < i || cred_desc.attribute_requests[i].idx != i){
                AttributeRequest r;
                r.idx = i;
                cred_desc.attribute_requests.push_back(r);
            }
        }
    }

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
    proof_json["serial"] = proof.serial;
    
    return proof_json;
}

void ZkidRPCServer::SetProofHandler(ZkidProofHandler *handler)
{
    this->_proof_handler = handler;
}