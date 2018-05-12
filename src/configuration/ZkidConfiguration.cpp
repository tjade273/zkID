#include "configuration/ZkidConfiguration.h"

ZkidConfiguration::ZkidConfiguration(const std::string &path_to_config) : _config(JsonObjectFromFile(path_to_config))
{
}

//ConfigCredentialsInterface
std::string ZkidConfiguration::GetCredentialsFilePath()
{
    return _config["credentials_file"].asString();
}

//ConfigRPCServerInterface
int ZkidConfiguration::GetServicePort()
{
    return _config["service_port"].asInt();
}

//ConfigProverInterface
std::string ZkidConfiguration::GetMerkleTreeEndpoint(const std::string &issuer)
{
    return _config["merkle_tree_endpoints"][issuer].asString();
}

std::string ZkidConfiguration::GetIPFSClientIP(){
    return _config["ipfs_client_ip"].asString();
}

int ZkidConfiguration::GetIPFSClientPort(){
    return _config["ipfs_client_port"].asInt();
}