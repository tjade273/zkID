#ifndef _LIBSNARK_HELPERS
#define _LIBSNARK_HELPERS
#include <iostream>
#include <string>
#include <iomanip>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/bigint.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libsnark
{
void bit_vector_from_string(libff::bit_vector &vect, const std::string &s);

std::string hex_from_bit_vector(const libff::bit_vector &vect);

/** Take from Zokrates **/

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);

std::array<std::string, 2> outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);

std::array<std::string, 4> outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);
}
#endif
