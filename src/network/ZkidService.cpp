#include "network/ZkidService.h"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

std::shared_ptr<spdlog::logger> ZkidService::console = spdlog::stderr_color_mt("zkid");

ZkidService::ZkidService(ConfigZkidServiceInterface *service_config, CredentialsManager *cred_manager, zkidMTProvider *mt_provider) : _service_config(service_config), _cred_manager(cred_manager), _http_server(service_config->GetServicePort()), _mt_provider(mt_provider)

{
    _rpc_server = std::make_shared<ZkidRPCServer>(_http_server, _service_config);
    if (dynamic_cast<jsonrpc::AbstractServerConnector *>(&_http_server)->GetHandler() == NULL)
        exit(0);
    _rpc_server->SetProofHandler(this);
};

bool ZkidService::Start()
{
    return _rpc_server->StartListening();
}

void ZkidService::Stop()
{
    _rpc_server->StopListening();
    console->info("Stopped zkid service on port {0}.", _service_config->GetServicePort());
}

bool ZkidService::GetProofForCredential(CredentialRequest &cred, CredentialProof &proof)
{
    if (cred.attribute_requests.size() < ZKID_CREDENTIAL_ATTRIBUTE_NUM)
    {
        for (int i = 0; i < ZKID_CREDENTIAL_ATTRIBUTE_NUM; i++)
        {
            if (cred.attribute_requests.size() < i || cred.attribute_requests[i].idx != i)
            {
                AttributeRequest r;
                r.idx = i;
                cred.attribute_requests.push_back(r);
            }
        }
    }

    std::string attribute_string;

    for (int i = 0; i < cred.attribute_requests.size(); i++)
    {
        auto cur_attribute = cred.attribute_requests[i];
        attribute_string +=
            "\t attribute_index: " + std::to_string(cur_attribute.idx) + "\n" +
            "\t lower_bound: " + cur_attribute.lower_bound + "\n" +
            "\t upper_bound: " + cur_attribute.upper_bound + "\n \n";
    }

    console->info("Recieved request for proof of credential: \n \
    ---------------------------------------------------------------------------- \n \
    contract_salt: {0} \n \
    merkle_root_address: {1} \n \ 
    k_bound: {2} \n \
    Attributes: \n \
    {3}\
    ---------------------------------------------------------------------------- \n",
                  cred.contract_salt, cred.merkle_root_address, cred.k_bound, attribute_string);

    return GenerateProofForCredential(cred, proof);
}

int ZkidService::GetPort()
{
    return _service_config->GetServicePort();
}

bool ZkidService::GenerateProofForCredential(const CredentialRequest &cred_request, CredentialProof &proof)
{
    const std::string issuer_address = cred_request.contract_salt;
    if (!_cred_manager->HasCredential(issuer_address))
    {
        console->error("User does not have a credential from: {0}", issuer_address);
        return false;
    }
    Credential cred = _cred_manager->GetCredential(issuer_address);

    std::vector<std::string> merkle_path;

    if (cred_request.merkle_root_address.empty())
    {
        console->error("Merkle address blank");
        return false;
    }
    std::string merkle_root = _mt_provider->GetMerklePath(cred_request.merkle_root_address, cred.merkle_address, merkle_path);
    if (merkle_path.empty())
    {
        console->error("Unable to get merkle path from: {0}", cred_request.merkle_root_address);
        return false;
    }

    zkidProverImpl<sha256_two_to_one_hash_gadget> prover(merkle_path.size(), 32);

    ProofRequest proof_request = ConstructProofRequest(cred_request, cred, merkle_root, merkle_path);
    LibsnarkCredentialProof libsnark_data;
    return prover.GetCredentialProof(proof_request, proof, libsnark_data);
}

ProofRequest ConstructProofRequest(const CredentialRequest &req, const Credential &cred, const std::string &merkle_root, const std::vector<std::string> merkle_path)
{
    ProofRequest pr;

    pr.secret_key = cred.secret_key;
    pr.merkle_root = merkle_root;
    pr.path = merkle_path;
    pr.address = cred.merkle_address;
    pr.attributes = cred.attributes;
    pr.k_bound = req.k_bound;
    pr.k = cred.k;
    pr.salt = req.contract_salt;

    for (auto attr_req : req.attribute_requests)
    {
        pr.lower_bounds += attr_req.lower_bound;
        pr.upper_bounds += attr_req.upper_bound;
    }

    return pr;
}
