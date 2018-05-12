#ifndef _CredentialsManager_h
#define _CredentialsManager_h

#include <unordered_map>
#include <string>
#include "configuration/ConfigCredentialsInterface.h"
#include "util/json_helpers.h"

struct Credential{
    Credential(){};
    Credential(std::string a, std::string l, std::string u, int kb, int _k, std::string cs, 
        std::string sn,uint ma) : attributes(a), 
                                          lower_bound(l),
                                          upper_bound(u),
                                          k(_k),
                                          k_bound(kb),
                                          contract_salt(cs),
                                          serial_number(sn),
                                          merkle_address(ma){};
    std::string contract_salt;
    std::string lower_bound;
    std::string upper_bound;
    int k_bound;
    std::string serial_number;
    std::string attributes;
    int k;
    uint merkle_address;
};

class CredentialsManager{
    public:
        CredentialsManager(ConfigCredentialsInterface* cred_config) : _cred_config(cred_config){}
        void LoadCredentials();
        bool HasCredential(const std::string& issuer_address);
        Credential GetCredential(const std::string& issuer_address);

    private:
        ConfigCredentialsInterface* _cred_config;
        std::unordered_map<std::string,Credential> _credentials; //this may be redundant since the issuer address is in the token.
};

#endif