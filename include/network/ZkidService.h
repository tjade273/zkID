#ifndef _ZkidService_h
#define _ZkidService_h

#include <spdlog/spdlog.h>
#include <memory>
#include "configuration/ConfigZkidServiceInterface.h"
#include "credentials/CredentialsManager.h"
#include "network/ZkidRPCServer.h"
#include "proving/zkidMTProvider.h"

class ZkidService : public ZkidProofHandler
{

  public:
    ZkidService(ConfigZkidServiceInterface* service_config, CredentialsManager* cred_manager, zkidMTProvider* mt_provider);

    static std::shared_ptr<spdlog::logger> console;
    bool Start();
    void Stop();
    bool GetProofForCredential(const CredentialRequest &cred, CredentialProof& proof);
    int GetPort();
  protected:
  virtual bool GenerateProofForCredential(const CredentialRequest &cred, CredentialProof &proof);

  protected:
    ConfigZkidServiceInterface *_service_config;
    std::shared_ptr<ZkidRPCServer> _rpc_server;

  private:
    jsonrpc::HttpServer _http_server;
    CredentialsManager* _cred_manager = nullptr;
    zkidMTProvider* _mt_provider = nullptr;
};
#endif