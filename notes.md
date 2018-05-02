# Possible Features

    * Revocation
    * k-use creds
    * Proof-of-funds
      * Ideas: If someone has access to a proof and also knows the identity of the issuer then they necessarily have access to some amount of ETH
      * This probably won't work, since it is possible to simply buy the proof without knowledge of the person issuing it. Validity is easy to check.
      * Better idea is k-use tokens. Every 10000 blocks I re-lock the coins and get to reset my counter. I have to reveal the counter on every use, applications decide how many uses I can have per N blocks.
    * Range proofs/ bitwise revelation

# Open Questions

    * How do we tie funds to proving ability?
    * How do we make the verifier as general as possible while remaining efficient?
    * Do we want a separate prover/verifier per application, or a single central identity?
    * How efficient can this scheme be made with current precompiles?
    * What about with Sapling?
  
# Notes:

    * Need to decide what the distinguishing feature(s) of our system are
    * What consitutes an MVP?
    * What does implementation on Ethereum bring that Ian's NMC implementation doesn't?
    * What formal security proofs can we give?
    * We should definitely try out knapsack CRH for efficiency; that's just one extra assumption and may make the numbers look much better
    * MVP is probably: verification service attests to user's age, range proof shows user is over 18.
    * If you can link a proof of age to some other facet of the identity, then you get to withdraw the deposit.
    * Usage limits, k-use tokens- can measure time via blockhash, i.e. cred is VRF_s(blockhash(100*(latest/100))||i), so you only get a new credential every 100 blocks. 

    * Might be nice to try building a smart contract credential issuer, i.e. proof of locked funds or something that can be verified entirely on-chain. 
    * Voting? By using funds-forfeiting system we can make voting systems where instead of being unable to prove that you voted a certain way you can prove it but the proof necessarily entails a forfeiture of funds.
      * Maybe not? We would need an information-theoretic guarantee here, which is hard.
      * Probably not possible? I can always make a smart contract that simply rewards anyone who submits a vote for my party with some funds, without actually knowing who they are.

# Commitment attribute format
    
    * We can use multi-pedersen commitments to selectively reveal attributes. 
    * Have something like 5 range-provable attributes and unlimited number of revealable attributes.
    * For instance, revealable attribute is checkpoint_block_hash, range provable is index < N.
      * How do we prevent revealing attribute commitment from uniquely identifying a commitment?
    
    * We could also go with a nested merkle tree: commitment contains merkle root, we prove that we know the secret key to some commitment that contains a merkle root such that the given set of attributes are all in the tree
      * Hard to scale: need a separate merkle proof for every attribute to be revealsed.
    
