pragma solidity ^0.4.14;
import "./verifier.sol";

contract Issuer {
   function get_root() public constant returns(uint);
}

contract LotteryContract{
  using Verifier for *;

  uint256 constant OVER_18 = 18 << 32*6;
  uint256 constant US_CITIZEN = 0x00555341 << 32*5; // USA in ASCII
  uint256 constant RATE = 16;

  Issuer issuer;

  mapping (address => bool) participants;
  mapping (uint => bool) nullifiers;

  event Joined(address);
  event Err(uint);

  modifier check_credentials(uint[18] data, uint serial, uint upper, uint lower) {
    uint m_root = issuer.get_root();
    uint salt = uint(this) << 56 | (block.number >> 12) << 32 | RATE;
    Verifier.Proof memory proof;
    proof.parseProofData(data);
    uint valid = Verifier.verify([m_root, serial, upper, lower, salt], proof);
    if(valid != 0 || nullifiers[serial]){
      Err(valid);
      return;
    }

    nullifiers[serial] = true;
    _;
  }

  function LotteryContract(address _issuer){
    issuer = Issuer(_issuer);
  }

  function Join(uint[18] proof, uint serial) check_credentials(proof, serial, US_CITIZEN, US_CITIZEN|OVER_18) public {
    participants[msg.sender] = true;
    Joined(msg.sender);
  }
}
