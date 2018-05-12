#ifndef _zkidMTProver_h
#define _zkidMTProver_h

#include <vector>
#include <string>

class zkidMTProvider
{
  public:
    virtual void GetMerklePath(const std::string &merkle_address, size_t address, std::vector<std::string> &path) = 0;
};
#endif