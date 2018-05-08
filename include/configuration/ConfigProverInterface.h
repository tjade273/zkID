#ifndef _ConfigProverInterface_h
#define _ConfigProverInterface_h

class ConfigProverInterface{
    virtual std::string GetMerkleTreeEndpoint(const std::string& issuer) = 0;
};

#endif