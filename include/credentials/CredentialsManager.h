#ifndef _CredentialsManager_h
#define _CredentialsManager_h

#include <unordered_map>
#include <string>
#include "configuration/ConfigCredentialsInterface.h"
#include "util/json_helpers.h"

class CredentialsManager{
    public:
        CredentialsManager(ConfigCredentialsInterface* cred_config) : _cred_config(cred_config){}
        void LoadCredentials();
        bool HasCredential(const std::string& issuer_address);
        const std::string& GetCredential(const std::string& issuer_address);

    private:
        ConfigCredentialsInterface* _cred_config;
        std::unordered_map<std::string,std::string> _credentials; //this may be redundant since the issuer address is in the token.
};

#endif