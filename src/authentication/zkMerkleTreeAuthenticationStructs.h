#ifndef _zkMerkleTreeAuthenticationStruct_h
#define _zkMerkleTreeAuthenticationStruct_h

#include <string>
#include <vector>
#include <array>

enum AuthenticationErrorCode
{
    //TODO: Define some error codes.
};

struct AuthenticationProof
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
    std::array<std::string,4> A;
    std::array<std::string,2> B;
    std::array<std::string,4> C;
    std::array<std::string,4> gamma;
    std::array<std::string,2> gammaBeta1;
    std::array<std::string,4> gammaBeta2;
    std::array<std::string,4> Z;
    std::array<std::string,2> IC0;
    std::vector<std::array<std::string,2>> ICs;
};

struct AuthenticationData
{
    VerificationKey key;
    AuthenticationProof proof;
};

struct AuthenticationNode
{
    bool is_right;
    std::string hash;
    AuthenticationNode(const std::string &_hash, bool _is_right) : hash(_hash), is_right(_is_right){};
    AuthenticationNode(){};
};

struct AuthenticationError
{
    AuthenticationError(){};
    AuthenticationError(const AuthenticationErrorCode &_ec, const std::string &_msg) : ec(_ec), msg(_msg) {}
    AuthenticationErrorCode ec;
    std::string msg;
};

#endif