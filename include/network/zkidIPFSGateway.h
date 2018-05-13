#ifndef _zkidIPFSGateway_h
#define _zkidIPFSGateway_h

#include <ipfs/client.h>
#include <nlohmann/json.hpp>
#include "proving/zkidMTProvider.h"
#include "configuration/ConfigIPFSInterface.h"

class zkidIPFSGateway : public zkidMTProvider
{
  public:
    zkidIPFSGateway(ConfigIPFSInterface* ipfs_config);
    void Connect(pid_t pid = 0);
    std::string GetMerklePath(const std::string &merkle_address, size_t address, std::vector<std::string> &path);
    std::string PutMerkleTree(const std::vector<std::string>& hashes, int i = 0);
  private:
    ipfs::Client _client;
    ConfigIPFSInterface* _ipfs_config = nullptr;
};
#endif