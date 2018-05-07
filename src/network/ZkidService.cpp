#include "network/ZkidService.h"

ZkidService::ZkidService(ConfigZkidServiceInterface *service_config)
    _http_server(service_config->GetServiceAddress()),
    _rpc_server(_http_server, _service_config)
{
    _rpc_server->SetProofHandler(this);
};

void ZkidService::Start()
{
    _rpc_server.StartListening();
    console->info("Started zkid service at address {0} successfully!", _service_config->GetServiceAddress());
    getchar();
}

void ZkidService::Stop()
{
    _rpc_server.StopListening();
    console->info("Stopped zkid service at {0}.", _service_config->GetServiceAddress());
}

bool ZkidService::GetProofForCredential(const CredentialDescription &cred, VerificationProof &proof)
{
    console->info("Recieved request for proof of credential: \n 
        issuer_address: {0} \n
        range_low: {1} \n
        range_high: {2} \n
        k_factor: {3} \n", cred.issuer_address, cred.range_low, cred.range_high, cred.k_factor);

        
    return GenerateProof(cred, proof);
}

std::string CredentialDescriptionToString(){

}

bool ZkidRPCServer::GenerateProofForCredential(const CredentialDescription &cred, VerificationProof &proof)
{
    zkidProver prover(_service_config);

    const std::string issuer_address = cred.issuer_address;
    if (!_cred_manager->HasCredential(issuer_address))
    {
        return false;
    }

    const std::string credential = _cred_manager->GetCredential(issuer_address);

    return prover.GenerateProof(credential, issuer_address, cred.range_low, cred.range_high, cred.k_factor, proof))
}
