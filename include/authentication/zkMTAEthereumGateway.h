#ifndef _zkMTAEtherumGateway_h
#define _zkMTAEtherumGateway_h
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include "zkMTAStructs.h"

class zkMTAEtherumGateway {
    public:
        bool Connect(const std::string& ip, int port);
        const bool Authenticate(const AuthenticationData& auth_data,const std::string& to);
    private:
        
};
#endif