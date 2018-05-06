pragma solidity ^0.4.0;
library CredentialsUser {
    struct Credential{
        string signature;
        string description;
    }

    struct CredentialUserData{
        mapping(string => Credential[]) action_credential_map;
    }
    
    function GetRequiredCredentialCount(CredentialUserData storage self, sting action) returns (uint count){
        return self.action_credential_map[action].length;
    }
    
    function GetRequiredCredential(CredentialUserData storage self, string action, uint index) returns (string signature, string description){
        Credential cred = self.action_credential_map[action][index];
        return (cred.signature, cred.description);
    }
}