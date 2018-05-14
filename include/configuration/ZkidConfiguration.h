#ifndef _ZkidConfiguration_h
#define _ZkidConfiguration_h

#include <jsoncpp/json/json.h>
#include "util/json_helpers.h"
#include "configuration/ConfigCredentialsInterface.h"
#include "configuration/ConfigZkidServiceInterface.h"
#include "configuration/ConfigIPFSInterface.h"

class ZkidConfiguration : public ConfigCredentialsInterface, public ConfigZkidServiceInterface, public ConfigIPFSInterface
{
public:
  ZkidConfiguration(const std::string &path_to_config);

  //ConfigCredentialsInterface
  std::string GetCredentialsFilePath();

  //ConfigRPCServerInterface
  int GetServicePort();

  //ConfigProverInterface
  std::string GetMerkleTreeEndpoint(const std::string &issuer);

  std::string GetKeyPath();

  //ConfigIPFSInterfance
  std::string GetIPFSClientIP();
  int GetIPFSClientPort();

private:
  Json::Value _config;
};
#endif
