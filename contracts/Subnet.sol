// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;
pragma experimental ABIEncoderV2;

import "./RLPEncode.sol";

contract Subnet {

  struct SubnetHeader {
    int number;
    uint64 round_num;
    uint64 gap_num;
    bytes32 parent_hash;
    bytes32 block_hash;
  }

  struct Header {
    bytes32 hash;
    int number;
    uint64 round_num;
    uint64 gap_num;
    bytes32 parent_hash;
    bool finalized;
    uint mainnet_num;
  }

  address public master;
  // bytes32[] public header_tree;
  mapping(bytes32 => Header) public header_tree;
  mapping(int => address[]) public validator_sets;
  mapping(address => bool) public lookup;
  int public current_validator_set_pointer = 0;
  bytes32 public latest_finalized_block;

  // Event types
  event SubnetBlockAccepted(bytes32 block_hash, int number);
  event SubnetBlockFinalized(bytes32 block_hash, int number);

  // Modifier
  modifier onlyMaster() {
    if (msg.sender != master) revert("Master Only");
    _;
  }

  constructor(address[] memory initial_validator_set, SubnetHeader memory genesis_header) public {
    require(initial_validator_set.length > 0, "Validator set cannot be empty");
    header_tree[genesis_header.block_hash] = Header({
      hash: genesis_header.block_hash,
      number: genesis_header.number,
      round_num: genesis_header.round_num, 
      gap_num: genesis_header.gap_num,
      parent_hash: genesis_header.parent_hash,
      finalized: true,
      mainnet_num: block.number
    });
    validator_sets[0] = initial_validator_set;
    for (uint i = 0; i < validator_sets[0].length; i++) {
      lookup[validator_sets[0][i]] = true;
    }
    master = msg.sender;
    latest_finalized_block = genesis_header.block_hash;
  }

  function reviseValidatorSet(address[] memory new_validator_set, int subnet_block_height) public onlyMaster  {
    require(new_validator_set.length > 0, "Validator set cannot be empty");
    require(subnet_block_height >= current_validator_set_pointer, "Error Modify Validator History");
    validator_sets[subnet_block_height] = new_validator_set;
  }

  function receiveHeader(SubnetHeader memory header, bytes[] memory sigs) public onlyMaster { 
    require(header.number > 0, "Error Modify Genesis");
    require(header_tree[header.parent_hash].hash != 0, "Parent Hash Not Found");
    require(header_tree[header.parent_hash].number + 1 == header.number, "Invalid Parent Relation");
    bytes32 header_hash = createHash(header);
    if (header_tree[header.block_hash].number > 0) 
      revert("Header has been submitted");
    if (validator_sets[header.number].length > 0) {
      for (uint i = 0; i < validator_sets[current_validator_set_pointer].length; i++) {
        lookup[validator_sets[current_validator_set_pointer][i]] = false;
      }
      for (uint i = 0; i < validator_sets[header.number].length; i++) {
        lookup[validator_sets[header.number][i]] = true;
      }
      current_validator_set_pointer = header.number;
    }
    if (sigs.length != validator_sets[current_validator_set_pointer].length)
      revert("Unmatched Amount between Signers and Validators");
    for (uint i = 0; i < sigs.length; i++) {
      address signer = recoverSigner(header_hash, sigs[i]);
      if (lookup[signer] != true) {
        revert("Verification Fail");
      }
    }
    header_tree[header.block_hash] = Header({
      hash: header.block_hash,
      number: header.number,
      round_num: header.round_num, 
      gap_num: header.gap_num,
      parent_hash: header.parent_hash,
      finalized: false,
      mainnet_num: block.number
    });
    emit SubnetBlockAccepted(header.block_hash, header.number);

    // Look for 3 consecutive round
    bytes32 curr_hash = header.block_hash;
    for (uint i = 0; i < 3; i++) {
      if (header_tree[curr_hash].parent_hash == 0) return;
      bytes32 parent_hash = header_tree[curr_hash].parent_hash;
      if (header_tree[curr_hash].round_num != header_tree[parent_hash].round_num+1) return;
      curr_hash = parent_hash;
    }
    latest_finalized_block = header_tree[curr_hash].hash;
    // Confirm all ancestor unconfirmed block
    while (header_tree[curr_hash].finalized != true) {
      header_tree[curr_hash].finalized = true;
      emit SubnetBlockFinalized(curr_hash, header_tree[curr_hash].number);
      curr_hash = header_tree[curr_hash].parent_hash;
    }
  }

  /// signature methods.
  function splitSignature(bytes memory sig)
    internal
    pure
    returns (uint8 v, bytes32 r, bytes32 s)
  {
    require(sig.length == 65, "Invalid Signature");
    assembly {
      // first 32 bytes, after the length prefix.
      r := mload(add(sig, 32))
      // second 32 bytes.
      s := mload(add(sig, 64))
      // final byte (first byte of the next 32 bytes).
      v := byte(0, mload(add(sig, 96)))
    }
    // TOCHECK: v needs 27 more, may related with EIP1559
    return (v+27, r, s);
  }

  function recoverSigner(bytes32 message, bytes memory sig)
    internal
    pure
    returns (address)
  {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
    return ecrecover(message, v, r, s);
  }

  function createHash(SubnetHeader memory header) internal pure returns (bytes32) {

    bytes[] memory x = new bytes[](3);
    x[0] = RLPEncode.encodeBytes(abi.encodePacked(header.block_hash));
    x[1] = RLPEncode.encodeUint(header.round_num);
    x[2] = RLPEncode.encodeUint(uint(header.number));

    bytes[] memory y = new bytes[](2);
    y[0] = RLPEncode.encodeList(x);
    y[1] = RLPEncode.encodeUint(header.gap_num);
    return keccak256(RLPEncode.encodeList(y));
  }

  function getHeader(bytes32 block_hash) public view returns (Header memory) {
    return header_tree[block_hash];
  }
  
  function getHeaderConfirmationStatus(bytes32 block_hash) public view returns (bool) {
    return header_tree[block_hash].finalized;
  }

  function getMainnetBlockNumber(bytes32 block_hash) public view returns (uint) {
    return header_tree[block_hash].mainnet_num;
  }

  function getLatestFinalizedBlock() public view returns (bytes32) {
    return latest_finalized_block;
  }

}