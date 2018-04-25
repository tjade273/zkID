#ifndef _zkMerkleTreeAuthenticator_h
#define _zkMerkleTreeAuthenticator_h

#include <fstream>
#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include "util/libsnark_helpers.h"

using namespace libsnark;
enum AuthenticationErrorCode
{
    //TODO: Define some error codes.
};

struct AuthenticationData
{
    //TODO: Figure out what this should look like
};

struct AuthenticationNode
{
    bool is_right;
    std::string hash;
    AuthenticationNode(const std::string &_hash, bool _is_right) : hash(_hash), is_right(_is_right){};
    AuthenticationNode(){};
};

struct AuthenticationError
{
    AuthenticationError(){};
    AuthenticationError(const AuthenticationErrorCode &_ec, const std::string &_msg) : ec(_ec), msg(_msg) {}
    AuthenticationErrorCode ec;
    std::string msg;
};

template <typename Field, template <typename> typename Hash>
class zkMerkleTreeAuthenticator
{
  public:
    zkMerkleTreeAuthenticator(){};

    typedef libff::Fr<Field> FieldT;
    typedef Hash<FieldT> HashT;

    bool Authenticate(const std::string &leaf_hash, const std::string &root_hash,
                      const std::vector<AuthenticationNode> &path, AuthenticationData &data)
    {
        Field::init_public_params();

        const size_t digest_len = HashT::get_digest_len();
        int tree_depth = path.size();
        libff::bit_vector address_bits;
        libff::bit_vector leaf(digest_len);
        libff::bit_vector root(digest_len);
        std::vector<libsnark::merkle_authentication_node> auth_path(tree_depth);
        size_t address = 0;

        this->ConstructPath(tree_depth, path, address, address_bits, auth_path);
        bit_vector_from_string(root, root_hash);
        bit_vector_from_string(leaf, leaf_hash);

        protoboard<FieldT> pb;
        this->FillPb(pb,leaf,root,address_bits,address,auth_path);

        if (pb.is_satisfied())
        {
            return this->GenerateAuthenticationData(pb, data);
        }
        else
        {
            return false;
        }
    }

    AuthenticationError GetError() const
    {
        return this->_e;
    }

  private:
    int _digest_len = HashT::get_digest_len();

    void FillPb(protoboard<FieldT> &pb, libff::bit_vector &leaf, libff::bit_vector &root,
                libff::bit_vector& address_bits, size_t &address, std::vector<libsnark::merkle_authentication_node> &auth_path)
    {
        int tree_depth = auth_path.size();
        pb_variable_array<FieldT> address_bits_va;
        address_bits_va.allocate(pb, auth_path.size(), "address_bits");
        digest_variable<FieldT> leaf_digest(pb, _digest_len, "input_block");
        digest_variable<FieldT> root_digest(pb, _digest_len, "output_digest");
        merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
        merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va,
                                                        leaf_digest, root_digest, path_var, ONE, "ml");

        path_var.generate_r1cs_constraints();
        ml.generate_r1cs_constraints();

        address_bits_va.fill_with_bits(pb, address_bits);

        leaf_digest.generate_r1cs_witness(leaf);
        path_var.generate_r1cs_witness(address, auth_path);
        ml.generate_r1cs_witness();

        address_bits_va.fill_with_bits(pb, address_bits);
        leaf_digest.generate_r1cs_witness(leaf);
        root_digest.generate_r1cs_witness(root);
    }

    bool GenerateAuthenticationData(protoboard<FieldT> &pb, AuthenticationData &auth_data)
    {
        //TODO: Generate the authentication data.
        return true;
    }

    void ConstructPath(int tree_depth, const std::vector<AuthenticationNode> &path, size_t &address,
                       libff::bit_vector &address_bits, std::vector<merkle_authentication_node> &auth_path)
    {

        for (int cur_depth = tree_depth - 1; cur_depth >= 0; cur_depth--)
        {
            const AuthenticationNode node = path[cur_depth];
            const std::string node_hash = node.hash;
            const bool is_right = node.is_right;

            address |= (!is_right ? 1ul << (tree_depth - 1 - cur_depth) : 0);
            address_bits.push_back(!is_right);

            libff::bit_vector cur_node_bv(HashT::get_digest_len());
            bit_vector_from_string(cur_node_bv, node_hash);
            auth_path[cur_depth] = cur_node_bv;
        }
    }
    AuthenticationError _e;
};

#endif