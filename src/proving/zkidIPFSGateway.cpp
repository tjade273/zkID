#include "proving/zkidIPFSGateway.h"

zkidIPFSGateway::zkidIPFSGateway(ConfigIPFSInterface* ipfs_config) : _ipfs_config(ipfs_config), _client(ipfs_config->GetIPFSClientIP(),ipfs_config->GetIPFSClientPort()){

}

std::vector<std::string> zkidIPFSGateway::GetIssuerMerkleTree(const std::string &issuer_address){
    /*TODO: 1. parse json file from string
            2. parse into json object
            3. iterate over and put all nodes into vector*/
}