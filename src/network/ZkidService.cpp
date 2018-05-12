#include "network/ZkidService.h"

std::shared_ptr<spdlog::logger> ZkidService::console = spdlog::stderr_color_mt("zkid");

ZkidService::ZkidService(ConfigZkidServiceInterface *service_config, CredentialsManager *cred_manager, zkidMTProvider* mt_provider) : 
    _service_config(service_config), _cred_manager(cred_manager), _http_server(service_config->GetServicePort()), _mt_provider(mt_provider)

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

bool ZkidService::GetProofForCredential(const CredentialRequest &cred, CredentialProof &proof)
{
    console->info("Recieved request for proof of credential: \n \
        issuer_address: {0} \n \
        merkle_root_address: {1} \n \
        range_low: {2} \n \
        range_high: {3} \n \
        k_factor: {4}",
                  cred.issuer_address, cred.merkle_root_address, cred.range_low, cred.range_high, cred.k_factor);

    return GenerateProofForCredential(cred, proof);
}

int ZkidService::GetPort()
{
    return _service_config->GetServicePort();
}

bool ZkidService::GenerateProofForCredential(const CredentialRequest &cred_request, CredentialProof &proof)
{
    zkidProver prover(_service_config);

    const std::string issuer_address = cred_request.issuer_address;
    if (!_cred_manager->HasCredential(issuer_address))
    {
        return false;
    }

    Credential cred = _cred_manager->GetCredential(issuer_address);
    std::vector<std::string> merkle_path;
    _mt_provider->GetMerklePath(cred_request.merkle_root_address,cred.address,merkle_path);
    return prover.GenerateProof(cred, cred_request, merkle_path, proof);
}
