#ifndef _zkidVerificationStructs_h
#define _zkidVerificationStructs_h

#include <array>
#include <vector>
#include <string>


enum VerificationErrorCode
{
    //TODO: Define some error codes.
};

struct CredentialRequest{
  std::string issuer_address;
  std::string merkle_root_address;
  uint32_t range_low;
  uint32_t range_high;
  uint32_t k_factor;
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

struct VerificationData
{
    CredentialProof proof;
};

struct VerificationError
{
    VerificationError(){};
    VerificationError(const VerificationErrorCode &_ec, const std::string &_msg) : ec(_ec), msg(_msg) {}
    VerificationErrorCode ec;
    std::string msg;
};
#endif