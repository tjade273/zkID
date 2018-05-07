#ifndef _ZkidRPCServer_h
#define _ZkidRPCServer_h

#include "network/AbstractZkidRPCServer.h"
#include "configuration/ConfigRPCServerInterface.h"
#include "credentials/CredentialsManager.h"
#include "proving/zkidProver.h"

class ZkidProofHandler
{
public:
  virtual bool GetProofForCredential(const CredentialDescription &cred, VerificationProof& proof) = 0;
};

class ZkidRPCServer : public AbstractZkidRPCServer
{

public:
  ZkidRPCServer(jsonrpc::AbstractServerConnector &conn, ConfigRPCServerInterface *rpc_config) : AbstractZkidRPCServer(conn),
                                                                                                _rpc_config(rpc_config) {}

  Json::Value GenerateProofs(const Json::Value &credential_descriptions);
  void SetProofHandler(ZkidProofHandler *listener);

private:
  static Json::Value ProofToJson(const VerificationProof &proof);
  static CredentialDescription CredentialDescriptionFromJson(const Json::Value &cred_json);

private:
  ConfigRPCServerInterface *_rpc_config = nullptr;
  ZkidProofHandler *_proof_handler = nullptr;
};

#endif