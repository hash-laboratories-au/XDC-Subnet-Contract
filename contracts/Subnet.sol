// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;
pragma experimental ABIEncoderV2;

import "./RLPEncode.sol";
import "./RLPReader.sol";

contract Subnet {

  struct Header {
    bytes32 hash;
    int number;
    uint64 round_num;
    bytes32 parent_hash;
    bool finalized;
    uint mainnet_num;
    bytes src;
  }

  address public master;
  // bytes32[] public header_tree;
  mapping(bytes32 => Header) public header_tree;
  mapping(int => address[]) public validator_sets;
  mapping(address => bool) public lookup;
  int public current_validator_set_pointer = 0;
  int public current_subnet_height;
  bytes32 public latest_finalized_block;

  // Event types
  event SubnetBlockAccepted(bytes32 header_hash, int number);
  event SubnetBlockFinalized(bytes32 header_hash, int number);

  // Modifier
  modifier onlyMaster() {
    if (msg.sender != master) revert("Master Only");
    _;
  }

  constructor(address[] memory initial_validator_set, bytes memory genesis_header) public {
    require(initial_validator_set.length > 0, "Validator set cannot be empty");
    bytes32 genesis_header_hash = keccak256(genesis_header);
    RLPReader.RLPItem[] memory ls = RLPReader.toList(RLPReader.toRlpItem(genesis_header));
    header_tree[genesis_header_hash] = Header({
      hash: genesis_header_hash,
      number: int(RLPReader.toUint(ls[8])),
      round_num: 0, 
      parent_hash: toBytes32(RLPReader.toBytes(ls[0])),
      finalized: true,
      mainnet_num: block.number,
      src: genesis_header
    });
    validator_sets[0] = initial_validator_set;
    for (uint i = 0; i < validator_sets[0].length; i++) {
      lookup[validator_sets[0][i]] = true;
    }
    master = msg.sender;
    latest_finalized_block = genesis_header_hash;
  }

  function reviseValidatorSet(address[] memory new_validator_set, int subnet_block_height) public onlyMaster  {
    require(new_validator_set.length > 0, "Validator set cannot be empty");
    require(subnet_block_height >= current_validator_set_pointer, "Error Modify Validator History");
    validator_sets[subnet_block_height] = new_validator_set;
  }

  function receiveHeader(bytes memory header) public onlyMaster { 
    RLPReader.RLPItem[] memory ls = RLPReader.toList(RLPReader.toRlpItem(header));
    int number = int(RLPReader.toUint(ls[8]));
    bytes32 parent_hash = toBytes32(RLPReader.toBytes(ls[0]));
    require(number > 0, "Error Modify Genesis");
    require(header_tree[parent_hash].hash != 0, "Parent Hash Not Found");
    require(header_tree[parent_hash].number + 1 == number, "Invalid Parent Relation");
    bytes32 header_hash = keccak256(header);
    if (header_tree[header_hash].number > 0) 
      revert("Header has been submitted");
    if (validator_sets[number].length > 0) {
      for (uint i = 0; i < validator_sets[current_validator_set_pointer].length; i++) {
        lookup[validator_sets[current_validator_set_pointer][i]] = false;
      }
      for (uint i = 0; i < validator_sets[number].length; i++) {
        lookup[validator_sets[number][i]] = true;
      }
      current_validator_set_pointer = number;
    }
    RLPReader.RLPItem[] memory extra = RLPReader.toList(RLPReader.toRlpItem(getExtraData(RLPReader.toBytes(ls[12]))));
    uint64 round_number = uint64(RLPReader.toUint(extra[0]));
    RLPReader.RLPItem[] memory sigs = RLPReader.toList(RLPReader.toList(extra[1])[1]);
    if (sigs.length != validator_sets[current_validator_set_pointer].length)
      revert("Unmatched Amount between Signers and Validators");
    for (uint i = 0; i < sigs.length; i++) {
      address signer = recoverSigner(header_hash, RLPReader.toBytes(sigs[i]));
      if (lookup[signer] != true) {
        revert("Verification Fail");
      }
    }
    header_tree[header_hash] = Header({
      hash: header_hash,
      number: number,
      round_num: round_number,
      parent_hash: parent_hash,
      finalized: false,
      mainnet_num: block.number,
      src: header
    });
    emit SubnetBlockAccepted(header_hash, number);

    // Look for 3 consecutive round
    bytes32 curr_hash = header_hash;
    for (uint i = 0; i < 3; i++) {
      if (header_tree[curr_hash].parent_hash == 0) return;
      bytes32 parent_hash = header_tree[curr_hash].parent_hash;
      if (header_tree[curr_hash].round_num != header_tree[parent_hash].round_num+1) return;
      curr_hash = parent_hash;
    }
    latest_finalized_block = curr_hash;
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

  function getExtraData(bytes memory extra) public pure returns (bytes memory) {
    bytes memory extraData = new bytes(extra.length-1);
    uint extraDataPtr;
    uint extraPtr;
    assembly { extraDataPtr := add(extraData, 0x20) }
    assembly { extraPtr := add(extra, 0x21) }
    RLPEncode.memcpy(extraDataPtr, extraPtr, extra.length-1);
    return extraData;
  }

  function toBytes32(bytes memory data) internal pure returns (bytes32 res) {
    assembly {
      res := mload(add(data, 32))
    }
  }

  function getHeader(bytes32 header_hash) public view returns (bytes memory) {
    return header_tree[header_hash].src;
  }
  
  function getHeaderConfirmationStatus(bytes32 header_hash) public view returns (bool) {
    return header_tree[header_hash].finalized;
  }

  function getMainnetBlockNumber(bytes32 header_hash) public view returns (uint) {
    return header_tree[header_hash].mainnet_num;
  }

  function getLatestFinalizedBlock() public view returns (bytes32) {
    return latest_finalized_block;
  }

}