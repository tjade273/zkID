#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "proving/zkidProverImpl.h"
#include "util/zkid_helpers.h"

int main(int argc, char* argv[])
{
  int tree_depth = atoi(argv[1]);
  libff::alt_bn128_pp::init_public_params();
  zkidProverImpl<sha256_two_to_one_hash_gadget> zkid(tree_depth, 32);
  zkid.ExportKeys(argv[2]);
}
