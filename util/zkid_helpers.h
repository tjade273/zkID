#ifndef _zk_identity_helpers_h
#define _zk_identity_helpers_h

#include <string>
#include <vector>
#include <iostream>
#include <regex>
#include <fstream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "authentication/zkidVerificationStructs.h"
#include "util/libsnark_helpers.h"
#include "json.hpp"

struct LibsnarkVerificationData
{
  libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;
  libsnark::r1cs_ppzksnark_primary_input<libff::alt_bn128_pp> primary_input;
};

VerificationProof ExtractVerificationProof(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> &proof);

VerificationKey ExtractVerificationKey(libsnark::r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> &vk);

std::string FormatG1(std::array<std::string, 2> p);

std::string FormatG2(std::array<std::string, 4> p);

void ExportVerificationKey(VerificationKey &vk, const std::string &sol_path, const std::string &out_path);

void ExportProof(LibsnarkVerificationData &auth, std::string fname);
#endif
