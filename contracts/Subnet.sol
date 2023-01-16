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

  struct Validators {
    address[] set;
    int threshold;
  }

  address public master;
  // bytes32[] public header_tree;
  mapping(bytes32 => Header) public header_tree;
  mapping(int => Validators) validator_sets;
  mapping(address => bool) lookup;
  mapping(address => bool) unique_addr;
  int public current_validator_set_pointer = 0;
  int public current_subnet_height;
  bytes32 public latest_finalized_block;

  // Event types
  event SubnetBlockAccepted(bytes32 block_hash, int number);
  event SubnetBlockFinalized(bytes32 block_hash, int number);

  // Modifier
  modifier onlyMaster() {
    if (msg.sender != master) revert("Master Only");
    _;
  }

  constructor(address[] memory initial_validator_set, int threshold, bytes memory genesis_header) public {
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
    validator_sets[0] = Validators({
      set: initial_validator_set,
      threshold: threshold
    });
    for (uint i = 0; i < initial_validator_set.length; i++) {
      lookup[initial_validator_set[i]] = true;
    }
    master = msg.sender;
    latest_finalized_block = genesis_header_hash;
  }

  function reviseValidatorSet(address[] memory new_validator_set, int threshold, int subnet_block_height) public onlyMaster  {
    require(new_validator_set.length > 0, "Validator set cannot be empty");
    require(threshold > 0, "Validation threshold cannot be 0");
    require(subnet_block_height >= current_validator_set_pointer, "Error Modify Validator History");
    validator_sets[subnet_block_height] = Validators({
      set: new_validator_set,
      threshold: threshold
    });
  }

  function receiveHeader(bytes memory header) public onlyMaster { 
    RLPReader.RLPItem[] memory ls = RLPReader.toList(RLPReader.toRlpItem(header));
    int number = int(RLPReader.toUint(ls[8]));
    bytes32 parent_hash = toBytes32(RLPReader.toBytes(ls[0]));
    RLPReader.RLPItem[] memory extra = RLPReader.toList(RLPReader.toRlpItem(getExtraData(RLPReader.toBytes(ls[12]))));
    uint64 round_number = uint64(RLPReader.toUint(extra[0]));
    require(number > 0, "Error Modify Genesis");
    require(header_tree[parent_hash].hash != 0, "Parent Hash Not Found");
    require(header_tree[parent_hash].number + 1 == number, "Invalid Parent Relation");
    require(header_tree[parent_hash].round_num < round_number, "Invalid Round Number");
    bytes32 block_hash = keccak256(header);
    if (header_tree[block_hash].number > 0) 
      revert("Header has been submitted");
    if (validator_sets[number].set.length > 0) {
      for (uint i = 0; i < validator_sets[current_validator_set_pointer].set.length; i++) {
        lookup[validator_sets[current_validator_set_pointer].set[i]] = false;
      }
      for (uint i = 0; i < validator_sets[number].set.length; i++) {
        lookup[validator_sets[number].set[i]] = true;
      }
      current_validator_set_pointer = number;
    }
    RLPReader.RLPItem[] memory sigs = RLPReader.toList(RLPReader.toList(extra[1])[1]);
    uint64 gap_number = uint64(RLPReader.toUint(RLPReader.toList(extra[1])[2]));

    bytes32 signHash = createSignHash(parent_hash, round_number, number, gap_number);
    int unique_counter = 0;
    address[] memory signer_list = new address[](sigs.length);
    for (uint i = 0; i < sigs.length; i++) {
      address signer = recoverSigner(signHash, RLPReader.toBytes(sigs[i]));
      if (lookup[signer] != true) {
        continue;
      }
      if (!unique_addr[signer]) {
        unique_counter ++;
        unique_addr[signer]=true;
      }
      signer_list[i] = signer;
    }
    for (uint i = 0; i < signer_list.length; i++) {
      unique_addr[signer_list[i]] = false;
    }
    if (unique_counter < validator_sets[current_validator_set_pointer].threshold) {
      revert("Verification Fail");
    }
    header_tree[block_hash] = Header({
      hash: block_hash,
      number: number,
      round_num: round_number,
      parent_hash: parent_hash,
      finalized: false,
      mainnet_num: block.number,
      src: header
    });
    emit SubnetBlockAccepted(block_hash, number);

    // Look for 3 consecutive round
    bytes32 curr_hash = block_hash;
    for (uint i = 0; i < 3; i++) {
      if (header_tree[curr_hash].parent_hash == 0) return;
      bytes32 prev_hash = header_tree[curr_hash].parent_hash;
      if (header_tree[curr_hash].round_num != header_tree[prev_hash].round_num+1) return;
      curr_hash = prev_hash;
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

  function createSignHash(bytes32 block_hash, uint64 round_num, int number, uint64 gap_num) internal pure returns (bytes32 signHash) {
    bytes[] memory x = new bytes[](3);
    x[0] = RLPEncode.encodeBytes(abi.encodePacked(block_hash));
    x[1] = RLPEncode.encodeUint(round_num);
    x[2] = RLPEncode.encodeUint(uint(number));

    bytes[] memory y = new bytes[](2);
    y[0] = RLPEncode.encodeList(x);
    y[1] = RLPEncode.encodeUint(gap_num);
    signHash = keccak256(RLPEncode.encodeList(y));
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

  function getValidatorSet(int height) public view returns (address[] memory res) {
    if (validator_sets[height].threshold == 0) {
      res = new address[](0);
    } else {
      res = validator_sets[height].set;
    }
  }

  function getValidatorThreshold(int height) public view returns (int res) {
    if (validator_sets[height].threshold == 0) {
      res = 0;
    } else {
      res = validator_sets[height].threshold;
    }
  }
}