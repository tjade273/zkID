#ifndef _zk_identity_helpers_h
#define _zk_identity_helpers_h

#include <string>
#include <vector>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "src/authentication/zkMerkleTreeAuthenticationStructs.h"
#include "util/libsnark_helpers.h"

#include "json.hpp"
using json = nlohmann::json;

void AuthenticationArgsFromJson(const std::string &path_to_json, std::string &leaf, std::string &root,
                                std::vector<AuthenticationNode> &path)
{
    //read in test file;
    std::ifstream f(path_to_json);

    if (!f)
        std::cout << "Failed to open file stream" << std::endl;

    json j;
    f >> j;

    root = j["root"];
    leaf = j["leaf"];
    json path_hashes = j["path"];
    int tree_depth = path_hashes.size();

    path.resize(tree_depth);

    //construct authentication path
    json::iterator cur_node_it = path_hashes.begin();
    for (int cur_depth = tree_depth - 1; cur_depth >= 0; ++cur_node_it, --cur_depth)
    {
        const std::string node_hash = (*cur_node_it)["hash"];
        const bool is_right = (*cur_node_it)["right"];
        path[cur_depth] = AuthenticationNode(node_hash, is_right);
    }
}

AuthenticationProof ExtractAuthenticationProof(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> &proof)
{
    AuthenticationProof p;

    p.A = libsnark::outputPointG1AffineAsHex(proof.g_A.g);
    p.A_p = libsnark::outputPointG1AffineAsHex(proof.g_A.h);
    p.B = libsnark::outputPointG2AffineAsHex(proof.g_B.g);
    p.B_p = libsnark::outputPointG1AffineAsHex(proof.g_B.h);
    p.C = libsnark::outputPointG1AffineAsHex(proof.g_C.g);
    p.C_p = libsnark::outputPointG1AffineAsHex(proof.g_C.h);
    p.H = libsnark::outputPointG1AffineAsHex(proof.g_H);
    p.K = libsnark::outputPointG1AffineAsHex(proof.g_K);
    return p;
}

VerificationKey ExtractVerificationKey(libsnark::r1cs_ppzksnark_verification_key<libff::alt_bn128_pp>& vk)
{
    VerificationKey k;
    
    int icLength = vk.encoded_IC_query.rest.indices.size() + 1;

    k.A = libsnark::outputPointG2AffineAsHex(vk.alphaA_g2);
    k.B = libsnark::outputPointG1AffineAsHex(vk.alphaB_g1);
    k.C = libsnark::outputPointG2AffineAsHex(vk.alphaC_g2);
    k.gamma = libsnark::outputPointG2AffineAsHex(vk.gamma_g2);
    k.gammaBeta1 = libsnark::outputPointG1AffineAsHex(vk.gamma_beta_g1);
    k.gammaBeta2 = libsnark::outputPointG2AffineAsHex(vk.gamma_beta_g2);
    k.ICs.resize(icLength);
    k.Z = libsnark::outputPointG2AffineAsHex(vk.rC_Z_g2);
    k.ICs[0] = libsnark::outputPointG1AffineAsHex(vk.encoded_IC_query.first);
    for (size_t i = 1; i < icLength; ++i)
    {
        auto vkICi = libsnark::outputPointG1AffineAsHex(vk.encoded_IC_query.rest.values[i - 1]);
        k.ICs[i] = vkICi;
    }

    return k;
}

#endif