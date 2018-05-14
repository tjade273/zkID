pragma solidity ^0.4.14;

contract Issuer {
  function merkle_root() public constant returns(uint);
  function ipfs_hash() public constant returns (string);
}
