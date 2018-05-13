#ifndef _zkidVerificationStructs_h
#define _zkidVerificationStructs_h

#include <array>
#include <vector>
#include <string>
#include <climits>

#define ZKID_CREDENTIAL_ATTRIBUTE_NUM 7

enum VerificationErrorCode
{
    //TODO: Define some error codes.
};

struct Credential
{
    Credential(){};
    Credential(std::string a, std::string key, int _k, std::string cs, size_t ma) : attributes(a),
                                                                         k(_k),
                                                                         contract_salt(cs),
                                                                         secret_key(key),
                                                                         merkle_address(ma){};
    std::string secret_key;
    std::string contract_salt;
    std::string attributes;
    int k;
    size_t merkle_address;
};

struct AttributeRequest
{
    std::string lower_bound = "0x00";
    std::string upper_bound = "0x7FFFFFFF";
    int idx;
};

struct CredentialRequest
{
    std::string contract_salt;
    std::string merkle_root_address;
    std::vector<AttributeRequest> attribute_requests;
    int k_bound;
};

struct CredentialProof
{
    std::array<std::string, 2> A;
    std::array<std::string, 2> A_p;
    std::array<std::string, 4> B;
    std::array<std::string, 2> B_p;
    std::array<std::string, 2> C;
    std::array<std::string, 2> C_p;
    std::array<std::string, 2> H;
    std::array<std::string, 2> K;
};

struct VerificationKey
{
    std::array<std::string, 4> A;
    std::array<std::string, 2> B;
    std::array<std::string, 4> C;
    std::array<std::string, 4> gamma;
    std::array<std::string, 2> gammaBeta1;
    std::array<std::string, 4> gammaBeta2;
    std::array<std::string, 4> Z;
    std::array<std::string, 2> IC0;
    std::vector<std::array<std::string, 2>> ICs;
};

struct VerificationError
{
    VerificationError(){};
    VerificationError(const VerificationErrorCode &_ec, const std::string &_msg) : ec(_ec), msg(_msg) {}
    VerificationErrorCode ec;
    std::string msg;
};
#endif