#include "zkid_helpers.h"

void ExtractCredentialProof(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> &proof, CredentialProof& p)
{
    p.A = libsnark::outputPointG1AffineAsHex(proof.g_A.g);
    p.A_p = libsnark::outputPointG1AffineAsHex(proof.g_A.h);
    p.B = libsnark::outputPointG2AffineAsHex(proof.g_B.g);
    p.B_p = libsnark::outputPointG1AffineAsHex(proof.g_B.h);
    p.C = libsnark::outputPointG1AffineAsHex(proof.g_C.g);
    p.C_p = libsnark::outputPointG1AffineAsHex(proof.g_C.h);
    p.H = libsnark::outputPointG1AffineAsHex(proof.g_H);
    p.K = libsnark::outputPointG1AffineAsHex(proof.g_K);
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
  return  p[0]+ ", " + p[1];
}

std::string FormatG2(std::array<std::string, 4> p)
{
  return  "[" + p[0] +  ", "  + p[1] + "], ["  + p[2] + ", "  + p[3]+"]";
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

void ExportProof(LibsnarkCredentialProof &auth, std::string fname)
{
    CredentialProof proof;
    ExtractCredentialProof(auth.proof, proof);

    std::ofstream f(fname);
    if (!f)
    {
        std::cerr << "Could not open proof export file" << std::endl;
        return;
    }
    f << "["<< FormatG1(proof.A) << ", "
      << FormatG1(proof.A_p) << ", "
      << FormatG2(proof.B) << ", "
      << FormatG1(proof.B_p) << ", "
      << FormatG1(proof.C) << ", "
      << FormatG1(proof.C_p) << ", "
      << FormatG1(proof.H) << ", "
      << FormatG1(proof.K) << "]" << std::endl << std::endl;

    f << "[";
    for (int i = 0; i < auth.primary_input.size() - 1; i++)
    {
      f << "\"0x" << libsnark::HexStringFromLibsnarkBigint(auth.primary_input[i].as_bigint()) << "\", ";
    }
    f << "\"0x" << libsnark::HexStringFromLibsnarkBigint(auth.primary_input[auth.primary_input.size() - 1].as_bigint()) << "\"]";
    f.close();
}
