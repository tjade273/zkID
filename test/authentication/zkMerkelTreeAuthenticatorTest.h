#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "authentication/zkMTA.h"
#include "util/zk_identity_helpers.h"

TEST(zkMTATest, TestAuthenticate){
    zkMTA<sha256_two_to_one_hash_gadget> authenticator;
    std::string root;
    std::string leaf;
    std::vector<AuthenticationNode> path;
    AuthenticationData authentication_data;

    AuthenticationArgsFromJson("test/res/merkle_path_test_pass.json",leaf,root,path);

    bool authenticated = authenticator.Authenticate(leaf,root,path,authentication_data);
    ASSERT_TRUE(authenticated);
}


TEST(zkMTATest, TestVerify){
    zkMTA<sha256_two_to_one_hash_gadget> authenticator;
    std::string root;
    std::string leaf;
    std::vector<AuthenticationNode> path;
    AuthenticationData authentication_data;

    AuthenticationArgsFromJson("test/res/merkle_path_test_pass.json",leaf,root,path);

    LibsnarkAuthenticationData libsnark_data;
    authenticator.Authenticate(leaf,root,path,authentication_data,&libsnark_data);

    const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(libsnark_data.pvk,libsnark_data.primary_input,libsnark_data.proof);

    ASSERT_TRUE(verified);
}

TEST(zkMTATest, TestVerifyFail){
  zkMTA<sha256_two_to_one_hash_gadget> authenticator;
  std::string root;
  std::string leaf;
  std::vector<AuthenticationNode> path;
  AuthenticationData authentication_data;

  AuthenticationArgsFromJson("test/res/merkle_path_test_fail.json",leaf,root,path);

  LibsnarkAuthenticationData libsnark_data;
  authenticator.Authenticate(leaf,root,path,authentication_data,&libsnark_data);

  const bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(libsnark_data.pvk,libsnark_data.primary_input,libsnark_data.proof);

  ASSERT_FALSE(verified);

}
