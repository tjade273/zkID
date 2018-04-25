#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "src/authentication/zkMerkleTreeAuthenticator.h"
#include "util/zk_identity_helpers.h"

TEST(zkMerkleTreeAuthenticatorTest, TestAuthenticate){
    zkMerkleTreeAuthenticator<libff::alt_bn128_pp,sha256_two_to_one_hash_gadget> authenticator;
    std::string root;
    std::string leaf;
    std::vector<AuthenticationNode> path;
    AuthenticationData authentication_data;

    AuthenticationArgsFromJson("test/res/merkle_path_test_pass.json",leaf,root,path);

    bool authenticated = authenticator.Authenticate(leaf,root,path,authentication_data);
    ASSERT_TRUE(authenticated);
}