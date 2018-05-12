pragma solidity ^0.4.14;
import "./verifier.sol";

contract LotteryContract{
    mapping (address => bool) participants; //TODO: is there a better way to do a set?
    
    function Join(uint[] proofs) public {
        require(Verifier.verifyTx(proofs,proofs.length));
        participants[msg.sender] = true;
    }
}