#ifndef _ZkidService_h
#define _ZkidService_h

#include <spdlog/spdlog.h>
#include "configuration/ConfigZkidServiceInterface.h"
#include "network/ZkidRCPServer.h"

class ZkidService : public ZkidProofHandler
{

  public:
    ZkidService(ConfigZkidServiceInterface *service_config, CredentialsManager *cred_manager) : service_config(service_config), _cred_manager(cred_manager){};

    static std::shared_ptr<spdlog::logger> console;
    void Start();
    void Stop();
    bool GetProofForCredential(const CredentialDescription &cred, VerificationProof& proof);

  protected:
    virtual VerificationProof GenerateProofForCredential(const Json::Value &credential_descriptions);

  protected:
    ConfigZkidServiceInterface *_service_config;
    ZkidRPCServer _rpc_server;

  private:
    HttpServer _http_server;
    CredentialsManager *_cred_manager = nullptr;
};
#endif