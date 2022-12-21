// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;
pragma experimental ABIEncoderV2;

import "./RLPEncode.sol";
import "./RLPReader.sol";

contract Subnet {

  struct SubnetHeader {
    bytes32 parent_hash;
    bytes32 uncle_hash;
    address coinbase;
    bytes32 root;
    bytes32 txHash;
    bytes32 receiptAddress;
    bytes bloom;
    int difficulty;
    int number;
    uint64 gasLimit;
    uint64 gasUsed;
    int time;
    bytes extra;
    bytes32 mixHash;
    bytes8 nonce;
    bytes validators;
    bytes validator;
    bytes penalties;
  }

  struct Header {
    bytes32 hash;
    uint64 round_num;
    bytes32 parent_hash;
    bytes32 uncle_hash;
    address coinbase;
    bytes32 root;
    bytes32 txHash;
    bytes32 receiptAddress;
    bytes bloom;
    int difficulty;
    int number;
    uint64 gasLimit;
    uint64 gasUsed;
    int time;
    bytes extra;
    bytes32 mixHash;
    bytes8 nonce;
    bytes validators;
    bytes validator;
    bytes penalties;
    bool finalized;
    uint mainnet_num;
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

  constructor(address[] memory initial_validator_set, SubnetHeader memory genesis_header) public {
    require(initial_validator_set.length > 0, "Validator set cannot be empty");
    bytes32 genesis_header_hash = createHash(genesis_header);
    header_tree[genesis_header_hash] = Header({
      hash: genesis_header_hash,
      round_num: 0, 
      parent_hash: genesis_header.parent_hash,
      uncle_hash: genesis_header.uncle_hash,
      coinbase: genesis_header.coinbase,
      root: genesis_header.root,
      txHash: genesis_header.txHash,
      receiptAddress: genesis_header.receiptAddress,
      bloom: genesis_header.bloom,
      difficulty: genesis_header.difficulty,
      number: genesis_header.number,
      gasLimit: genesis_header.gasLimit,
      gasUsed: genesis_header.gasUsed,
      time: genesis_header.time,
      extra: genesis_header.extra,
      mixHash: genesis_header.mixHash,
      nonce: genesis_header.nonce,
      validators: genesis_header.validators,
      validator: genesis_header.validator,
      penalties: genesis_header.penalties,
      finalized: true,
      mainnet_num: block.number
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

  function receiveHeader(SubnetHeader memory header, bytes[] memory sigs) public onlyMaster { 
    require(header.number > 0, "Error Modify Genesis");
    require(header_tree[header.parent_hash].hash != 0, "Parent Hash Not Found");
    require(header_tree[header.parent_hash].number + 1 == header.number, "Invalid Parent Relation");
    bytes32 header_hash = createHash(header);
    if (header_tree[header_hash].number > 0) 
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
    header_tree[header_hash] = Header({
      hash: header_hash,
      round_num: getRoundNumber(header.extra),
      parent_hash: header.parent_hash,
      uncle_hash: header.uncle_hash,
      coinbase: header.coinbase,
      root: header.root,
      txHash: header.txHash,
      receiptAddress: header.receiptAddress,
      bloom: header.bloom,
      difficulty: header.difficulty,
      number: header.number,
      gasLimit: header.gasLimit,
      gasUsed: header.gasUsed,
      time: header.time,
      extra: header.extra,
      mixHash: header.mixHash,
      nonce: header.nonce,
      validators: header.validators,
      validator: header.validator,
      penalties: header.penalties,
      finalized: false,
      mainnet_num: block.number
    });
    emit SubnetBlockAccepted(header_hash, header.number);

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

  function prefixed(bytes memory data) internal pure returns (bytes32) {
    // TODO: keccak256 => sha256, remove prefix
    return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", data.length, data));
  }

  function createHash(SubnetHeader memory header) internal pure returns (bytes32) {

    bytes[] memory x = new bytes[](18);
    x[0] = RLPEncode.encodeBytes(abi.encodePacked(header.parent_hash));
    x[1] = RLPEncode.encodeBytes(abi.encodePacked(header.uncle_hash));
    x[2] = RLPEncode.encodeAddress(header.coinbase);
    x[3] = RLPEncode.encodeBytes(abi.encodePacked(header.root));
    x[4] = RLPEncode.encodeBytes(abi.encodePacked(header.txHash));
    x[5] = RLPEncode.encodeBytes(abi.encodePacked(header.receiptAddress));
    x[6] = RLPEncode.encodeBytes(header.bloom);
    x[7] = RLPEncode.encodeInt(header.difficulty);
    x[8] = RLPEncode.encodeInt(header.number);
    x[9] = RLPEncode.encodeUint(header.gasLimit);
    x[10] = RLPEncode.encodeUint(header.gasUsed);
    x[11] = RLPEncode.encodeInt(header.time);
    x[12] = RLPEncode.encodeBytes(header.extra);
    x[13] = RLPEncode.encodeBytes(abi.encodePacked(header.mixHash));
    x[14] = RLPEncode.encodeBytes(abi.encodePacked(header.nonce));
    x[15] = RLPEncode.encodeBytes(header.validators);
    x[16] = RLPEncode.encodeBytes(header.validator);
    x[17] = RLPEncode.encodeBytes(header.penalties);

    bytes32 header_hash = keccak256(RLPEncode.encodeList(x));
    return header_hash;
  }

  function getRoundNumber(bytes memory extra) public pure returns (uint64) {
    bytes memory extraData = new bytes(extra.length-1);
    uint extraDataPtr;
    uint extraPtr;
    assembly { extraDataPtr := add(extraData, 0x20) }
    assembly { extraPtr := add(extra, 0x21) }
    RLPEncode.memcpy(extraDataPtr, extraPtr, extra.length-1);
    RLPReader.RLPItem[] memory ls = RLPReader.toList(RLPReader.toRlpItem(extraData));
    return uint64(RLPReader.toUint(ls[0]));
  }

  function encoding(uint64 number, uint64 round_num, bytes32 parent_hash) pure public returns (bytes memory) {
    bytes[] memory x = new bytes[](3);
    x[0] = RLPEncode.encodeUint(number);
    x[1] = RLPEncode.encodeUint(round_num);
    x[2] = RLPEncode.encodeBytes(abi.encodePacked(parent_hash));
    return RLPEncode.encodeList(x);
  }

  function getHeader(bytes32 header_hash) public view returns (Header memory) {
    return header_tree[header_hash];
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