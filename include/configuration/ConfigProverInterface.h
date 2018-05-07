#ifndef _ConfigProverInterface_h
#define _ConfigProverInterface_h

class ConfigProverInterface{
    virtual const std::string& GetMerkleTreeEndpoint() = 0;
};

#endif