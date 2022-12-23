const { forContractInstance } =  require("@truffle/decoder");
const RLP = require("rlp");
const util = require("@ethereumjs/util");
const secp256k1 = require("secp256k1");
const Subnet = artifacts.require("Subnet");

const num2Arr = (n) => {
  if (!n) return new Uint8Array(0)
  const a = []
  a.unshift(n & 255)
  while (n >= 256) {
    n = n >>> 8
    a.unshift(n & 255)
  }
  return new Uint8Array(a);
}

const hex2Arr = (hexString) => {
  if (hexString.length % 2 !== 0) {
      throw "Must have an even number of hex digits to convert to bytes";
  }
  var numBytes = hexString.length / 2;
  var byteArray = new Uint8Array(numBytes);
  for (var i=0; i<numBytes; i++) {
      byteArray[i] = parseInt(hexString.substr(i*2, 2), 16);
  }
  return byteArray;
}


contract("Subnet test", async accounts => {

  beforeEach(async () => {
    this.validators = [];
    this.validators_addr = [];
    this.genesis_block = {
      "number": 0,
      "round_num": 0,
      "gap_num": 0,
      "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "block_hash": "0x1000000000000000000000000000000000000000000000000000000000000000"
    }
    this.genesis_cert_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([[
        "0x1000000000000000000000000000000000000000000000000000000000000000",
        util.bigIntToUnpaddedBuffer(0),
        util.bigIntToUnpaddedBuffer(0),
    ], util.bigIntToUnpaddedBuffer(0)])));

    for (let i = 0; i < 3; i++) {
      this.validators.push(web3.eth.accounts.create());
      this.validators_addr.push(this.validators.at(-1).address);
    }
    this.subnet = await Subnet.new(
      this.validators_addr,
      this.genesis_block,
      {"from": accounts[0]}
    );
    this.decoder = await forContractInstance(this.subnet);
  })

  it("Running setup", async() => {
    const master = await this.subnet.master();
    const validators = [];
    for (let i = 0; i < 3; i++) {
      validators.push(await this.subnet.validator_sets(0, i));
    }
    assert.equal(master, accounts[0]);
    assert.deepEqual(validators, this.validators_addr);
  });

  it("Revise Validator Set", async() => {
    const new_validators = [];
    for (let i = 0; i < 3; i++) {
      new_validators.push(web3.eth.accounts.create().address);
    }

    await this.subnet.reviseValidatorSet(new_validators, 4, {"from": accounts[0]});
    const validators = [];
    for (let i = 0; i < 3; i++) {
      validators.push(await this.subnet.validator_sets(4, i));
    }
    assert.deepEqual(validators, new_validators);
  });

  it("Receive New Header", async() => {
    const new_validators = [];
    const raw_sigs = [];
    const block1 = {
      "number": 1,
      "round_num": 0,
      "gap_num": 0,
      "parent_hash": "0x1000000000000000000000000000000000000000000000000000000000000000",
      "block_hash": "0x2000000000000000000000000000000000000000000000000000000000000000"
    };
    const block1_cert_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([[
        "0x2000000000000000000000000000000000000000000000000000000000000000",
        util.bigIntToUnpaddedBuffer(0),
        util.bigIntToUnpaddedBuffer(1),
    ], util.bigIntToUnpaddedBuffer(0)])));
    for (let i = 0; i < 3; i++) {
      new_validators.push(web3.eth.accounts.create());
      raw_sigs.push(
        secp256k1.ecdsaSign(
          hex2Arr(block1_cert_hash.substring(2)),
          hex2Arr(new_validators.at(-1).privateKey.substring(2))
      ));
    }

    const sigs = raw_sigs.map(x => {
      var res = new Uint8Array(65);
      res.set(x.signature, 0);
      res.set([x.recid], 64);
      return "0x"+Buffer.from(res).toString("hex");
    });

    await this.subnet.reviseValidatorSet(
      new_validators.map(x => x.address), 
      1, {"from": accounts[0]}
    );
    
    await this.subnet.receiveHeader(block1, sigs);

    const block1_resp = await this.subnet.getHeader("0x2000000000000000000000000000000000000000000000000000000000000000");
    assert.equal(block1_resp.parent_hash, "0x1000000000000000000000000000000000000000000000000000000000000000");
    assert.equal(block1_resp.round_num, "0");
    assert.equal(block1_resp.number, "1");
    assert.equal(block1_resp.gap_num, "0");

    const finalized = await this.subnet.getHeaderConfirmationStatus("0x2000000000000000000000000000000000000000000000000000000000000000");
    const mainnet_num = await this.subnet.getMainnetBlockNumber("0x2000000000000000000000000000000000000000000000000000000000000000");
    const latest_finalized_block = await this.subnet.getLatestFinalizedBlock();
    assert.equal(finalized, false);
    assert.equal(latest_finalized_block, "0x1000000000000000000000000000000000000000000000000000000000000000");
  });

  it("Confirm A Received Block", async() => {

    const composeBlock = (number, round_num, gap_num, parent_hash, block_hash) => {
      var block = {
        "number": number,
        "round_num": round_num,
        "gap_num": gap_num,
        "parent_hash": parent_hash,
        "block_hash": block_hash
      }
      var block_cert_hash = web3.utils.sha3(Buffer.from(
        RLP.encode([[
          util.toBuffer(block_hash),
          util.bigIntToUnpaddedBuffer(round_num),
          util.bigIntToUnpaddedBuffer(number),
      ], util.bigIntToUnpaddedBuffer(gap_num)])));
      return [block, block_cert_hash];
    }

    const signBlock = (block_cert_hash, validators) => {
      var raw_sigs = []
      for (let i = 0; i < 3; i++) {
        raw_sigs.push(
          secp256k1.ecdsaSign(
            hex2Arr(block_cert_hash.substring(2)),
            hex2Arr(validators[i].privateKey.substring(2))
        ));
      }
      return raw_sigs.map(x => {
        var res = new Uint8Array(65);
        res.set(x.signature, 0);
        res.set([x.recid], 64);
        return "0x"+Buffer.from(res).toString("hex");
      });
    }
    

    var [block1, block1_cert_hash] = composeBlock(1, 0, 0, "0x1000000000000000000000000000000000000000000000000000000000000000", "0x2000000000000000000000000000000000000000000000000000000000000000");
    var [block2, block2_cert_hash] = composeBlock(2, 1, 0, "0x2000000000000000000000000000000000000000000000000000000000000000", "0x3000000000000000000000000000000000000000000000000000000000000000");
    var [block3, block3_cert_hash] = composeBlock(3, 2, 0, "0x3000000000000000000000000000000000000000000000000000000000000000", "0x4000000000000000000000000000000000000000000000000000000000000000");
    var [block4, block4_cert_hash] = composeBlock(4, 3, 0, "0x4000000000000000000000000000000000000000000000000000000000000000", "0x5000000000000000000000000000000000000000000000000000000000000000");

    let sigs1 = signBlock(block1_cert_hash, this.validators);
    let sigs2 = signBlock(block2_cert_hash, this.validators);
    let sigs3 = signBlock(block3_cert_hash, this.validators);
    let sigs4 = signBlock(block4_cert_hash, this.validators);

    await this.subnet.receiveHeader(block1, sigs1); 
    await this.subnet.receiveHeader(block2, sigs2);
    await this.subnet.receiveHeader(block3, sigs3);
    await this.subnet.receiveHeader(block4, sigs4);

    const block1_resp = await this.subnet.getHeader("0x2000000000000000000000000000000000000000000000000000000000000000");
    assert.equal(block1_resp.parent_hash, "0x1000000000000000000000000000000000000000000000000000000000000000");
    assert.equal(block1_resp.round_num, "0");
    assert.equal(block1_resp.number, "1");
    assert.equal(block1_resp.gap_num, "0");

    const finalized = await this.subnet.getHeaderConfirmationStatus("0x2000000000000000000000000000000000000000000000000000000000000000");
    const mainnet_num = await this.subnet.getMainnetBlockNumber("0x2000000000000000000000000000000000000000000000000000000000000000");
    const latest_finalized_block = await this.subnet.getLatestFinalizedBlock();
    assert.equal(finalized, true);
    assert.equal(latest_finalized_block, "0x2000000000000000000000000000000000000000000000000000000000000000");
  });

  it("Lookup the transaction", async() => {
    const raw_sigs = [];
    const block1 = {
      "number": 1,
      "round_num": 0,
      "gap_num": 0,
      "parent_hash": "0x1000000000000000000000000000000000000000000000000000000000000000",
      "block_hash": "0x2000000000000000000000000000000000000000000000000000000000000000"
    };
    const block1_cert_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([[
        util.toBuffer("0x2000000000000000000000000000000000000000000000000000000000000000"),
        util.bigIntToUnpaddedBuffer(0),
        util.bigIntToUnpaddedBuffer(1),
    ], util.bigIntToUnpaddedBuffer(0)])));
    for (let i = 0; i < 3; i++) {
      raw_sigs.push(
        secp256k1.ecdsaSign(
          hex2Arr(block1_cert_hash.substring(2)),
          hex2Arr(this.validators[i].privateKey.substring(2))
      ));
    }

    const sigs = raw_sigs.map(x => {
      var res = new Uint8Array(65);
      res.set(x.signature, 0);
      res.set([x.recid], 64);
      return "0x"+Buffer.from(res).toString("hex");
    });

    await this.subnet.receiveHeader(block1, sigs);
    const mainnet_num = await this.subnet.getMainnetBlockNumber("0x2000000000000000000000000000000000000000000000000000000000000000");
    const transactionCount = await web3.eth.getBlockTransactionCount(mainnet_num);
    for (let i = 0; i < transactionCount; i++) {
      let transaction = await web3.eth.getTransactionFromBlock(mainnet_num, i);
      let decodeData = await this.decoder.decodeTransaction(transaction);
      let block_cert_hash = web3.utils.sha3(Buffer.from(
        RLP.encode([[
          util.toBuffer(decodeData.arguments[0].value.value[4].value.value.asHex),
          util.bigIntToUnpaddedBuffer(decodeData.arguments[0].value.value[1].value.value.asBN),
          util.bigIntToUnpaddedBuffer(decodeData.arguments[0].value.value[0].value.value.asBN),
      ], util.bigIntToUnpaddedBuffer(decodeData.arguments[0].value.value[2].value.value.asBN)])));
      console.log(block_cert_hash);
      console.log(block1_cert_hash);
    }
  });
})