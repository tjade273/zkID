pragma solidity ^0.4.14;
import "./issuer.sol";

contract ExampleIssuer is Issuer {
  uint public merkle_root;
  string public ipfs_hash;
  address owner;

  function ExampleIssuer(){
    owner = msg.sender;
  }

  function update(uint _merkle_root, string _ipfs_hash) public {
    if(msg.sender != owner)
      revert();

    merkle_root = _merkle_root;
    ipfs_hash = _ipfs_hash;
  }
}
