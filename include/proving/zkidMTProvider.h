#ifndef _zkidMTProver_h
#define _zkidMTProver_h

#include <vector>
#include <string>

class zkidMTProvider
{
  public:
    virtual std::vector<std::string> GetIssuerMerkleTree(const std::string &issuer_address) = 0;
};
#endif