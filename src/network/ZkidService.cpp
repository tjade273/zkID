#include "network/ZkidService.h"

std::shared_ptr<spdlog::logger> ZkidService::console = spdlog::stderr_color_mt("zkid");

ZkidService::ZkidService(ConfigZkidServiceInterface *service_config, CredentialsManager *cred_manager) : _service_config(service_config), _cred_manager(cred_manager), _http_server(service_config->GetServicePort())

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

bool ZkidService::GetProofForCredential(const CredentialDescription &cred, VerificationProof &proof)
{
    console->info("Recieved request for proof of credential: \n \
        issuer_address: {0} \n \
        range_low: {1} \n \
        range_high: {2} \n \
        k_factor: {3}",
                  cred.issuer_address, cred.range_low, cred.range_high, cred.k_factor);

    return GenerateProofForCredential(cred, proof);
}

int ZkidService::GetPort()
{
    return _service_config->GetServicePort();
}

bool ZkidService::GenerateProofForCredential(const CredentialDescription &cred, VerificationProof &proof)
{
    zkidProver prover(_service_config);

    const std::string issuer_address = cred.issuer_address;
    if (!_cred_manager->HasCredential(issuer_address))
    {
        return false;
    }

    const std::string credential = _cred_manager->GetCredential(issuer_address);

    return prover.GenerateProof(credential, issuer_address, cred.range_low, cred.range_high, cred.k_factor, proof);
}
