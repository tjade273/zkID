#ifndef _LIBSNARK_HELPERS
#define _LIBSNARK_HELPERS

#include "libff/common/utils.hpp"

namespace libsnark
{
void bit_vector_from_string(libff::bit_vector &vect, const std::string &s)
{
    for (int i = 0; i < s.size(); i += 2)
    {
        unsigned int v;
        std::string hex_char = s.substr(i, 2);
        std::stringstream ss;
        ss << hex_char;
        ss >> std::hex >> v;
        for (int j = 7; j >= 0; j--)
        {
            vect[i * 4 + (7 - j)] = v & (1 << j);
        }
    }
}
}
#endif