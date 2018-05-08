#ifndef _zkidProver_h
#define _zkidProver_h

#include "configuration/ConfigProverInterface.h"
#include "zkidVerificationStructs.h"

class zkidProver{
    public:
        zkidProver(ConfigProverInterface* prover_config) : _prover_config(prover_config){};
        bool GenerateProof(const std::string& credential,const std::string& issuer_address, const std::string& range_low, 
            const std::string& range_high, const std::string& k_factor,VerificationProof& proof){return false; /* Actually generate a proof */};
    private:
        void RetrieveMerkleTree(const std::string& issuer_address);
        ConfigProverInterface* _prover_config = nullptr;
};
#endif