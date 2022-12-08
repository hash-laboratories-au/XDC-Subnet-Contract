// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;
pragma experimental ABIEncoderV2;

import "./RLPEncode.sol";
import "./BN256G1.sol";
import "./BN256G2.sol";


contract Subnet {

  struct SubnetHeader {
    uint64 number;
    uint64 round_num;
    bytes32 parent_hash;
  }

  struct Header {
    bytes32 hash;
    uint64 round_num;
    uint64 number;
    bytes32 parent_hash;
    bool finalized;
  }

  struct G1Point {
    uint256 X;
    uint256 Y;
  }

  struct G2Point {
    uint256 Xx;
    uint256 Xy;
    uint256 Yx;
    uint256 Yy;
  }

  address public master;
  // bytes32[] public header_tree;
  mapping(bytes32 => Header) public header_tree;
  mapping(uint64 => uint256[4]) public validator_sets;
  uint64 public current_validator_set_pointer = 0;
  uint64 public current_subnet_height;

  // Event types
  event SubnetBlockAccepted(bytes32 header_hash, uint64 number);
  event SubnetBlockFinalized(bytes32 header_hash, uint64 number);

  // Modifier
  modifier onlyMaster() {
    if (msg.sender != master) revert("Master Only");
    _;
  }

  constructor(G2Point[] memory initial_validator_set, SubnetHeader memory genesis_header) public {
    require(initial_validator_set.length > 0, "Validator set cannot be empty");
    bytes32 genesis_header_hash = createHash(genesis_header);
    header_tree[genesis_header_hash] = Header({
      hash: genesis_header_hash,
      round_num: 0, 
      number: 0,
      parent_hash: genesis_header.parent_hash,
      finalized: true
    });

    uint256 Xx;
    uint256 Xy;
    uint256 Yx;
    uint256 Yy;
    for (uint i = 0; i < initial_validator_set.length; i++) {
      (Xx, Xy, Yx, Yy) = BN256G2.ecTwistAdd(
        Xx, Xy, Yx, Yy, 
        initial_validator_set[i].Xx,
        initial_validator_set[i].Xy,
        initial_validator_set[i].Yx,
        initial_validator_set[i].Yy
      );
    }
    validator_sets[0] = [Xx, Xy, Yx, Yy];
    master = msg.sender;
  }

  function reviseValidatorSet(G2Point[] memory new_validator_set, uint64 subnet_block_height) public onlyMaster  {
    require(new_validator_set.length > 0, "Validator set cannot be empty");
    require(subnet_block_height >= current_validator_set_pointer, "Error Modify Validator History");
    uint256 Xx;
    uint256 Xy;
    uint256 Yx;
    uint256 Yy;
    for (uint i = 0; i < new_validator_set.length; i++) {
      (Xx, Xy, Yx, Yy) = BN256G2.ecTwistAdd(
        Xx, Xy, Yx, Yy, 
        new_validator_set[i].Xx,
        new_validator_set[i].Xy,
        new_validator_set[i].Yx,
        new_validator_set[i].Yy
      );
    }
    validator_sets[subnet_block_height] = [Xx, Xy, Yx, Yy];
  }

  function receiveHeader(SubnetHeader memory header, G1Point memory sig) public onlyMaster { 
    require(header.number > 0, "Error Modify Genesis");
    require(header_tree[header.parent_hash].hash != 0, "Parent Hash Not Found");
    require(header_tree[header.parent_hash].number + 1 == header.number, "Invalid Parent Relation");
    bytes32 header_hash = createHash(header);
    if (header_tree[header_hash].number > 0) 
      revert("Header has been submitted");
    if (validator_sets[header.number][0] > 0) {
      current_validator_set_pointer = header.number;
    }

    uint256[4] memory aggPubKey = validator_sets[current_validator_set_pointer];
    uint256 X;
    uint256 Y;
    (X, Y) = BN256G1.hashToTryAndIncrement(encoding(header));
    if (BN256G1.bn256CheckPairing(
      [X, Y, 
      aggPubKey[0], 
      aggPubKey[1], 
      aggPubKey[2],
      aggPubKey[3], 
      sig.X,
      sig.Y,
      BN256G2.PTXX, 
      BN256G2.PTXY,
      BN256G2.PTYX,
      BN256G2.PTYY]) == false) {
        revert("Verification Fail");
      }

    header_tree[header_hash] = Header({
      hash: header_hash,
      round_num: header.round_num, 
      number: header.number,
      parent_hash: header.parent_hash,
      finalized: false
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
    x[0] = RLPEncode.encodeUint(header.number);
    x[1] = RLPEncode.encodeUint(header.round_num);
    x[2] = RLPEncode.encodeBytes(abi.encodePacked(header.parent_hash));

    bytes32 header_hash = keccak256(RLPEncode.encodeList(x));
    return header_hash;
  }

  function encoding(SubnetHeader memory header) internal pure returns (bytes memory) {

    bytes[] memory x = new bytes[](3);
    x[0] = RLPEncode.encodeUint(header.number);
    x[1] = RLPEncode.encodeUint(header.round_num);
    x[2] = RLPEncode.encodeBytes(abi.encodePacked(header.parent_hash));
    return RLPEncode.encodeList(x);
  }


  function bytesFromGPoint(G2Point memory p) internal pure returns (bytes memory) {
    return abi.encodePacked([p.Xx, p.Xy, p.Yx, p.Yy]);
  }

  function getHeaderStatus(bytes32 header_hash) public view returns (Header memory) {
    return header_tree[header_hash];
  }

}