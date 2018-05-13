#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "proving/zkidProverImpl.h"
#include "util/zkid_helpers.h"


#define M_TREE_LENGTH 32

TEST(zkIDTest, TestProofGeneration){
  ProofRequest proof;
  CredentialProof verification_data;

  ProofRequestFromJson("test/res/test_credential_proof.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkidProverImpl<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);
  bool verifiable = authenticator.GetCredentialProof(proof, verification_data);
  ASSERT_TRUE(verifiable);
}

TEST(zkIDTest, TestVerify){
  ProofRequest proof;
  CredentialProof verification_data;

  ProofRequestFromJson("test/res/test_credential_proof.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkidProverImpl<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);

  LibsnarkCredentialProof libsnark_data;
  authenticator.GetCredentialProof(proof, verification_data, &libsnark_data);
  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(authenticator.GetVerificationKey(),
                                                         libsnark_data.primary_input,
                                                         libsnark_data.proof);

  ExportProof(libsnark_data, "test/res/proof.export");

  ASSERT_TRUE(verified);
}


TEST(zkIDTest, TestExportVerifier){
  zkidProverImpl<sha256_two_to_one_hash_gadget> zkid(M_TREE_LENGTH, 32);

  auto vk_pp = zkid.GetVerificationKey();
  VerificationKey vk = ExtractVerificationKey(vk_pp);

  ExportVerificationKey(vk, "test/res/verification.sol.tmpl", "test/res/verification.sol");
}

TEST(zkIDTest, TestVerifyFail){
  ProofRequest proof;
  CredentialProof verification_data;

  ProofRequestFromJson("test/res/test_credential_proof_fail.json", proof);
  libff::alt_bn128_pp::init_public_params();
  zkidProverImpl<sha256_two_to_one_hash_gadget> authenticator(proof.path.size(), 32);

  LibsnarkCredentialProof libsnark_data;
  authenticator.GetCredentialProof(proof, verification_data, &libsnark_data);
  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(authenticator.GetVerificationKey(),
                                                                               libsnark_data.primary_input,
                                                                               libsnark_data.proof);

  ASSERT_FALSE(verified);
}

