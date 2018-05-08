#ifndef _ZkidConfiguration_h
#define _ZkidConfiguration_h

#include <jsoncpp/json/json.h>
#include "util/json_helpers.h"
#include "configuration/ConfigCredentialsInterface.h"
#include "configuration/ConfigZkidServiceInterface.h"

class ZkidConfiguration : public ConfigCredentialsInterface, public ConfigZkidServiceInterface
{
  public:
    ZkidConfiguration(const std::string &path_to_config);

    //ConfigCredentialsInterface
    std::string GetCredentialsFilePath();

    //ConfigRPCServerInterface
    int GetServicePort();

    //ConfigProverInterface
    std::string GetMerkleTreeEndpoint(const std::string& issuer);

  private:
    Json::Value _config;
};
#endif