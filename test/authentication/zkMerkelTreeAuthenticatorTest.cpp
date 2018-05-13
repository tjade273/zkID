#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "proving/zkidMTA.h"
#include "util/zkid_helpers.h"


#define M_TREE_LENGTH 8

TEST(zkMTATest, TestProofGenerationPbSatisfaction){
    std::string root;
    std::string leaf;
    std::vector<MTAuthenticationNode> path;
    VerificationData verification_data;

    AuthenticationArgsFromJson("test/res/merkle_path_test_pass.json",leaf,root,path);
    printf("Path len: %d\n", path.size());
    libff::alt_bn128_pp::init_public_params();
    zkMTA<sha256_two_to_one_hash_gadget> authenticator(path.size());
    bool verifiable = authenticator.GetVerificationData(leaf,root,path,verification_data);
    ASSERT_TRUE(verifiable);
}

TEST(zkMTATest, TestVerify){
    std::string root;
    std::string leaf;
    std::vector<MTAuthenticationNode> path;
    VerificationData verification_data;

    AuthenticationArgsFromJson("test/res/merkle_path_test_pass.json",leaf,root,path);
    zkMTA<sha256_two_to_one_hash_gadget> authenticator(path.size());
    LibsnarkVerificationData libsnark_data;
    authenticator.GetVerificationData(leaf,root,path,verification_data,&libsnark_data);

    const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(authenticator.GetVerificationKey(),
      libsnark_data.primary_input,libsnark_data.proof);

    ExportProof(libsnark_data, "test/res/proof.export");

    ASSERT_TRUE(verified);
}

TEST(zkMTATest, TestExportVerifier){
  zkMTA<sha256_two_to_one_hash_gadget> zkidMTA(M_TREE_LENGTH);

  auto vk_pp = zkidMTA.GetVerificationKey();
  VerificationKey vk = ExtractVerificationKey(vk_pp);

  ExportVerificationKey(vk, "test/res/verification.sol.tmpl", "test/res/verification.sol");
}

TEST(zkMTATest, TestVerifyFail){
  std::string root;
  std::string leaf;
  std::vector<MTAuthenticationNode> path;
  VerificationData verification_data;

  AuthenticationArgsFromJson("test/res/merkle_path_test_fail.json",leaf,root,path);
  zkMTA<sha256_two_to_one_hash_gadget> authenticator(path.size());

  LibsnarkVerificationData libsnark_data;
  authenticator.GetVerificationData(leaf,root,path,verification_data,&libsnark_data);

  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(
      authenticator.GetVerificationKey(),libsnark_data.primary_input,libsnark_data.proof);

  ExportProof(libsnark_data, "test/res/proof.bad.export");

  ASSERT_FALSE(verified);
}


TEST(zkIDTest, TestProofGeneration){
  ProofRequest proof;
  VerificationData verification_data;

  ProofRequestFromJson("test/res/test_credential_proof.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkID<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);
  bool verifiable = authenticator.GetVerificationData(proof, verification_data);
  ASSERT_TRUE(verifiable);
}

TEST(zkIDTest, TestVerify){
  ProofRequest proof;
  VerificationData verification_data;

  ProofRequestFromJson("test/res/test_credential_proof.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkID<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);

  LibsnarkVerificationData libsnark_data;
  authenticator.GetVerificationData(proof, verification_data, &libsnark_data);
  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(authenticator.GetVerificationKey(),
                                                         libsnark_data.primary_input,
                                                         libsnark_data.proof);

  ExportProof(libsnark_data, "test/res/proof.export");

  ASSERT_TRUE(verified);
}


TEST(zkIDTest, TestExportVerifier){
  zkID<sha256_two_to_one_hash_gadget> zkid(M_TREE_LENGTH, 32);

  auto vk_pp = zkid.GetVerificationKey();
  VerificationKey vk = ExtractVerificationKey(vk_pp);

  ExportVerificationKey(vk, "test/res/verification.sol.tmpl", "test/res/verification.sol");
}

TEST(zkIDTest, TestVerifyFail){
  ProofRequest proof;
  VerificationData verification_data;

  ProofRequestFromJson("test/res/test_credential_proof_fail.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkID<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);

  LibsnarkVerificationData libsnark_data;
  authenticator.GetVerificationData(proof, verification_data, &libsnark_data);
  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(authenticator.GetVerificationKey(),
                                                                               libsnark_data.primary_input,
                                                                               libsnark_data.proof);

  ASSERT_FALSE(verified);
}

