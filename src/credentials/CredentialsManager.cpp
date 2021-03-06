#include "credentials/CredentialsManager.h"

bool CredentialsManager::HasCredential(const std::string& issuer_address){
    return _credentials.find(issuer_address) != _credentials.end();
}

Credential CredentialsManager::GetCredential(const std::string& issuer_address){
    return _credentials[issuer_address];
}

void CredentialsManager::LoadCredentials(){
    const std::string& credential_file = _cred_config->GetCredentialsFilePath();

    Json::Value creds_json = JsonObjectFromFile(credential_file);

    for(int i = 0; i < creds_json.size(); i++){
        Json::Value current_cred = creds_json[i];
        _credentials[current_cred["contract_salt"].asString()] = Credential(current_cred["attributes"].asString(), 
                                                                            current_cred["secret_key"].asString(),
                                                                            current_cred["k"].asUInt(),
                                                                            current_cred["contract_salt"].asString(),
                                                                            current_cred["merkle_address"].asInt());}
}