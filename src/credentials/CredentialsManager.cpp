#include "credentials/CredentialsManager.h"

bool CredentialsManager::HasCredential(const std::string& issuer_address){
    return _credentials.find(issuer_address) != _credentials.end();
}

Credential CredentialsManager::GetCredential(const std::string& issuer_address){
    return _credentials[issuer_address];
}

void CredentialsManager::LoadCredentials(){
    const std::string& credentials_directory = _cred_config->GetCredentialsFilePath();

    Json::Value creds_json = JsonObjectFromFile(credentials_directory);

    for(int i = 0; i < creds_json.size(); i++){
        Json::Value current_cred = creds_json[i];
        _credentials[current_cred["issuer_address"].asString()] = Credential(current_cred["token"].asInt(), current_cred["address"].asInt());
    }
}