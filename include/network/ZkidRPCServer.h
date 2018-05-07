#ifndef _ZkidRPCServer_h
#define _ZkidRPCServer_h

#include "network/AbstractZkidRPCServer.h"
#include "configuration/ConfigRPCServerInterface.h"
#include "credentials/CredentialsManager.h"
#include "proving/zkidProver.h"

class ZkidRPCServer : public AbstractZkidRPCServer
{

  public:
    ZkidRPCServer(jsonrpc::AbstractServerConnector &conn, CredentialsManager *cred_manager, ConfigRPCServerInterface* rpc_config) : AbstractZkidRPCServer(conn), 
      _cred_manager(cred_manager), _rpc_config(rpc_config){}

    virtual Json::Value GenerateProofs(const Json::Value &credential_descriptions);

  private:
    static Json::Value ProofToJson(const VerificationProof& proof);
  private:
    CredentialsManager* _cred_manager = nullptr;
    ConfigRPCServerInterface* _rpc_config = nullptr;
};

#endif