#ifndef _zkMTAClient_h
#define _zkMTAClient_h

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "zkMTAEthereumGateway.h"
#include "zkMTA.h"

class zkMTAClient
{
  public:
    
  private:
    zkMTA<sha256_two_to_one_hash_gadget> _authenticator;
    zkMTAEtherumGateway _gateway;
};
#endif