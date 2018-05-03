#include "zk_identity_helpers.h"

using json = nlohmann::json;

VerificationProof ExtractVerificationProof(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> &proof)
{
    VerificationProof p;

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

VerificationKey ExtractVerificationKey(libsnark::r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> &vk)
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

std::string FormatG1(std::array<std::string, 2> p)
{
    return p[0] + ", " + p[1];
}

std::string FormatG2(std::array<std::string, 4> p)
{
    return "[" + p[0] + ", " + p[1] + "], [" + p[2] + ", " + p[3] + "]";
}

void ExportVerificationKey(VerificationKey &vk, const std::string &sol_path, const std::string &out_path)
{

    std::ifstream f(sol_path);
    if (!f)
    {
        std::cerr << "Solidity template not found" << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << f.rdbuf();
    f.close();
    std::regex reg("<%vk_a%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG2(vk.A)));
    reg = std::regex("<%vk_b%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG1(vk.B)));
    reg = std::regex("<%vk_c%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG2(vk.C)));
    reg = std::regex("<%vk_g%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG2(vk.gamma)));
    reg = std::regex("<%vk_gb1%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG1(vk.gammaBeta1)));
    reg = std::regex("<%vk_gb2%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG2(vk.gammaBeta2)));
    reg = std::regex("<%vk_z%>");
    buffer.str(std::regex_replace(buffer.str(), reg, FormatG2(vk.Z)));
    reg = std::regex("<%vk_ic_length%>");
    buffer.str(std::regex_replace(buffer.str(), reg, std::to_string(vk.ICs.size())));

    std::stringstream ic_buffer;
    for (int i = 0; i < vk.ICs.size(); i++)
    {
        ic_buffer << "vk.IC[" << i << "] = Pairing.G1Point(" << FormatG1(vk.ICs[i]) << ");\n";
    }

    reg = std::regex("<%vk_ic_pts%>");
    buffer.str(std::regex_replace(buffer.str(), reg, ic_buffer.str()));

    reg = std::regex("<%vk_input_length%>");
    buffer.str(std::regex_replace(buffer.str(), reg, std::to_string(vk.ICs.size() - 1)));

    std::ofstream of(out_path);
    if (!of)
    {
        std::cerr << "Could not open output file";
        return;
    }
    of << buffer.str() << std::flush;
    of.close();
}

void ExportProof(LibsnarkVerificationData &auth, std::string fname)
{
    VerificationProof proof = ExtractVerificationProof(auth.proof);

    std::ofstream f(fname);
    if (!f)
    {
        std::cerr << "Could not open proof export file" << std::endl;
        return;
    }
    f << "event Verified(string);" << std::endl;
    f << "function verifyTx() returns (bool r) {" << std::endl;
    f << "\tuint[] memory input = new uint[](" << auth.primary_input.size() << ");" << std::endl;
    f << "\tProof memory proof;" << std::endl;

    f << "\tproof.A = Pairing.G1Point(" << FormatG1(proof.A) << ");" << std::endl;
    f << "\tproof.A_p = Pairing.G1Point(" << FormatG1(proof.A_p) << ");" << std::endl;
    f << "\tproof.B = Pairing.G2Point(" << FormatG2(proof.B) << ");" << std::endl;
    f << "\tproof.B_p = Pairing.G1Point(" << FormatG1(proof.B_p) << ");" << std::endl;
    f << "\tproof.C = Pairing.G1Point(" << FormatG1(proof.C) << ");" << std::endl;
    f << "\tproof.C_p = Pairing.G1Point(" << FormatG1(proof.C_p) << ");" << std::endl;
    f << "\tproof.H = Pairing.G1Point(" << FormatG1(proof.H) << ");" << std::endl;
    f << "\tproof.K = Pairing.G1Point(" << FormatG1(proof.K) << ");" << std::endl;

    for (int i = 0; i < auth.primary_input.size(); i++)
    {
        f << "\tinput[" << i << "] = 0x" << libsnark::HexStringFromLibsnarkBigint(auth.primary_input[i].as_bigint()) << ";" << std::endl;
    }
    f << "\tif (verify(input, proof) == 0) {\n\t\tVerified(\"Transaction successfully verified.\");\n\t\treturn true;\n\t} else {\n\t\treturn false;\n\t}\n}" << std::endl;

    f.close();
}
