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
      "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    }
    this.genesis_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([
        util.bigIntToUnpaddedBuffer(0),
        util.bigIntToUnpaddedBuffer(0),
        util.zeros(32),
    ])));

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
      "parent_hash": this.genesis_hash,
    };
    const block1_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([
        util.bigIntToUnpaddedBuffer(1),
        util.bigIntToUnpaddedBuffer(0),
        util.toBuffer(this.genesis_hash)
    ])));
    for (let i = 0; i < 3; i++) {
      new_validators.push(web3.eth.accounts.create());
      raw_sigs.push(
        secp256k1.ecdsaSign(
          hex2Arr(block1_hash.substring(2)),
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

    const block1_resp = await this.subnet.getHeader(block1_hash);
    assert.equal(block1_resp.parent_hash, this.genesis_hash);
    assert.equal(block1_resp.round_num, "0");
    assert.equal(block1_resp.number, "1");

    const finalized = await this.subnet.getHeaderConfirmationStatus(block1_hash);
    const mainnet_num = await this.subnet.getMainnetBlockNumber(block1_hash);
    assert.equal(finalized, false);
  });

  it("Confirm A Received Block", async() => {

    const composeBlock = (number, round_num, parent_hash) => {
      var block = {
        "number": number,
        "round_num": round_num,
        "parent_hash": parent_hash,
      }
      var block_hash = web3.utils.sha3(Buffer.from(
        RLP.encode([
          util.bigIntToUnpaddedBuffer(number),
          util.bigIntToUnpaddedBuffer(round_num),
          util.toBuffer(parent_hash),
      ])));
      return [block, block_hash];
    }

    const signBlock = (block_hash, validators) => {
      var raw_sigs = []
      for (let i = 0; i < 3; i++) {
        raw_sigs.push(
          secp256k1.ecdsaSign(
            hex2Arr(block_hash.substring(2)),
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
    

    var [block1, block1_hash] = composeBlock(1, 0, this.genesis_hash);
    var [block2, block2_hash] = composeBlock(2, 1, block1_hash);
    var [block3, block3_hash] = composeBlock(3, 2, block2_hash);
    var [block4, block4_hash] = composeBlock(4, 3, block3_hash);

    let sigs1 = signBlock(block1_hash, this.validators);
    let sigs2 = signBlock(block2_hash, this.validators);
    let sigs3 = signBlock(block3_hash, this.validators);
    let sigs4 = signBlock(block4_hash, this.validators);

    await this.subnet.receiveHeader(block1, sigs1); 
    await this.subnet.receiveHeader(block2, sigs2);
    await this.subnet.receiveHeader(block3, sigs3);
    await this.subnet.receiveHeader(block4, sigs4);

    const block1_resp = await this.subnet.getHeader(block1_hash);
    assert.equal(block1_resp.parent_hash, this.genesis_hash);
    assert.equal(block1_resp.round_num, "0");
    assert.equal(block1_resp.number, "1");
    const finalized = await this.subnet.getHeaderConfirmationStatus(block1_hash);
    const mainnet_num = await this.subnet.getMainnetBlockNumber(block1_hash);
    assert.equal(finalized, true);
  });

  it("Lookup the transaction", async() => {
    const raw_sigs = [];
    const block1 = {
      "number": 1,
      "round_num": 0,
      "parent_hash": this.genesis_hash,
    };
    const block1_hash = web3.utils.sha3(Buffer.from(
      RLP.encode([
        util.bigIntToUnpaddedBuffer(1),
        util.bigIntToUnpaddedBuffer(0),
        util.toBuffer(this.genesis_hash)
    ])));
    for (let i = 0; i < 3; i++) {
      raw_sigs.push(
        secp256k1.ecdsaSign(
          hex2Arr(block1_hash.substring(2)),
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
    const mainnet_num = await this.subnet.getMainnetBlockNumber(block1_hash);
    const transactionCount = await web3.eth.getBlockTransactionCount(mainnet_num);
    for (let i = 0; i < transactionCount; i++) {
      let transaction = await web3.eth.getTransactionFromBlock(mainnet_num, i);
      let decodeData = await this.decoder.decodeTransaction(transaction);
      let block_hash = web3.utils.sha3(Buffer.from(
        RLP.encode([
          util.bigIntToUnpaddedBuffer(decodeData.arguments[0].value.value[0].value.value.asBN),
          util.bigIntToUnpaddedBuffer(decodeData.arguments[0].value.value[1].value.value.asBN),
          util.toBuffer(decodeData.arguments[0].value.value[2].value.value.asHex)
      ])));
      console.log(block_hash);
    }
  });
})