#ifndef _zkidIPFSGateway_h
#define _zkidIPFSGateway_h

#include <ipfs/client.h>
#include "proving/zkidMTProvider.h"
#include "configuration/ConfigIPFSInterface.h"

class zkidIPFSGateway : public zkidMTProvider
{
  public:
    zkidIPFSGateway(ConfigIPFSInterface* ipfs_config);
    std::vector<std::string> GetIssuerMerkleTree(const std::string &issuer_address);

  private:
    ipfs::Client _client;
    ConfigIPFSInterface* _ipfs_config = nullptr;
};
#endif