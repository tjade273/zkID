#include "libsnark_helpers.h"

void libsnark::bit_vector_from_string(libff::bit_vector &vect, const std::string &s)
{
    for (int i = 0; i < s.size(); i += 2)
    {
        unsigned int v;
        std::string hex_char = s.substr(i, 2);
        std::stringstream ss;
        ss << hex_char;
        ss >> std::hex >> v;
        for (int j = 0; j < 8; j++)
        {
          vect[4*i + j] = v & (1 << (7-j));
        }
    }
}

std::string libsnark::hex_from_bit_vector(const libff::bit_vector &vect){
  std::stringstream ss;
  for(int i = 0; i < vect.size(); i+=8){
    unsigned int v = 0;
    for(int j = 0; j < 8; j++){
      v |= (vect[i + j] << (7-j));
    }
    ss << std::setfill('0') << std::setw(2) << std::hex << v;
  }
  return ss.str();
}

/** Take from Zokrates **/

std::string libsnark::HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 8; j++)
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i < 32; i++)
    {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, std::min(str.find_first_not_of('0'), str.size() - 1));
}

std::array<std::string, 2> libsnark::outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();
    return {"0x" + HexStringFromLibsnarkBigint(aff.X.as_bigint()),
            "0x" + HexStringFromLibsnarkBigint(aff.Y.as_bigint())};
}

std::array<std::string, 4> libsnark::outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();
    return {"0x" + HexStringFromLibsnarkBigint(aff.X.c1.as_bigint()),
            "0x" + HexStringFromLibsnarkBigint(aff.X.c0.as_bigint()),
            "0x" + HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint()),
            "0x" + HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint())};
}
