const assert = require('assert');
const prova = require('../index');
const script = require('../src/script');

describe('Admin', function() {
  describe('Funds Issuing Keys', function() {
    it('add issuing key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22bd025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      assert.strictEqual(transaction.outs[0].isAdminThreadOutput, true);
      assert.strictEqual(transaction.outs[0].adminThread, 0);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);
      const adminThreadOutputIndex = builder.getAdminThreadOutputIndex();
      assert.strictEqual(adminThreadOutputIndex, 0);

      const operation = prova.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.ROOT.ISSUANCE_KEY;
      const publicKey = prova.ECPair.fromPublicKeyBuffer(Buffer.from('025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, publicKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('revoke issuing key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22be025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.ROOT.ISSUANCE_KEY;
      const publicKey = prova.ECPair.fromPublicKeyBuffer(Buffer.from('025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, publicKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('add provisioning key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22bf025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.ROOT.PROVISIONING_KEY;
      const publicKey = prova.ECPair.fromPublicKeyBuffer(Buffer.from('025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, publicKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('revoke provisioning key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22c0025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.ROOT.PROVISIONING_KEY;
      const publicKey = prova.ECPair.fromPublicKeyBuffer(Buffer.from('025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, publicKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('add validating key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000251bb0000000000000000246a22c1025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.PROVISIONING.VALIDATOR_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('revoke validating key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000251bb0000000000000000246a22c2025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.PROVISIONING.VALIDATOR_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });
  });

  describe('Account Service Provider Keys', function() {
    it('add ASP key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000251bb0000000000000000286a26c3025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf10000010000000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.PROVISIONING.ACCOUNT_SERVICE_PROVIDER_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey, 65536);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });

    it('revoke ASP key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000251bb0000000000000000286a26c4025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf10000010000000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.ADMIN.KEY_TYPES.PROVISIONING.ACCOUNT_SERVICE_PROVIDER_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey, 65536);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });
  });

  describe('Fund Issuance', function() {
    it('should destroy some funds', function() {
      const txHex = '0100000002b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffffbd1efe69f058de9229343d782efa78153b5971635a5c3bba462ea81f3274e8880000000000ffffffff0200000000000000000252bb9001000000000000016a00000000';
      const transaction = prova.Transaction.fromHex(txHex);
      console.log('here');
    });

    it('should fully sign issuance transaction', () => {
      const privKeyHex = '2edbca7c596b1d6ac714678a9ab1352cbe80a2d28b9e3ed2f7b0ed759026cc52';
      const wspPrivKeyHex = 'eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694';

      const privateKey = prova.ECPair.fromPrivateKeyBuffer(
      Buffer.from(privKeyHex, 'hex'),
      prova.networks.rmg
      );

      const wspPrivKey = prova.ECPair.fromPrivateKeyBuffer(
      Buffer.from(wspPrivKeyHex, 'hex'),
      prova.networks.rmg
      );

      const txHex = '0100000002a94e1a3f48e4293f389e10ac98bf7d5e84e517ed1ebc48c9a2bec200b5895c3a0000000000ffffffffb570c88582dbac65b1366a5c72f885a0c40582e7bf274016e3733b7e4c112e1d0100000000ffffffff0200000000000000000252bbe803000000000000016a00000000';

      const prevAdminTxHex = '0100000001b570c88582dbac65b1366a5c72f885a0c40582e7bf274016e3733b7e4c112e1d00000000d52103337b5d7a1578f69270343a965eb5de2ea1fb8a38bd99f69b7c37b477e9ccbf6c47304402201206718f88fdea31780588d4c859c2e3f892ca8f3ad8060c757cdf8ceff73d5602201f39bebfb1c0d8e21abaf43c62d4fbc522658bb72fff77a144e15159ce41b7a601210333baa8beac868211a0af0617b223ffcef9e114d84839cc5c5b549680ac157eaf483045022100828ce53f92456f746fe05af7664cb991482a270e2306a9ebbd11b5e96981b6c602205dc3d9ccda2ae99c5bd368a41148fbc903460d041852f359940be7429a4620cc01ffffffff0200000000000000000252bbe8030000000000001d521435dbbf04bca061e49dace08f858d8775c0a57c8e510300000153ba00000000';
      const prevAdminTx = prova.Transaction.fromHex(prevAdminTxHex);

      const prevFundTxHex = '01000000013b43bc382b86dadfa204e2ecc2465d3cded22603ad9174f71994c386d364d68700000000d52103337b5d7a1578f69270343a965eb5de2ea1fb8a38bd99f69b7c37b477e9ccbf6c483045022100b5ae02965ad0b591e448ccda99522a1cbb27bc522e02e8efe07e101cd2f327cb02200bed84d97c0ab62ab2d34902aaa40c3c8f4c4e69234b979f8a73b918b18941e001210333baa8beac868211a0af0617b223ffcef9e114d84839cc5c5b549680ac157eaf47304402206ff643164738d5ac9d383290cad3c9a84080bb1e8f83d7343aa2c13378502a2c0220326d8de600d52b1b11aa2e5bfe4d5f7d384e02be15dea445f593149b2c1c527b01ffffffff0200000000000000000252bbe8030000000000001d521435dbbf04bca061e49dace08f858d8775c0a57c8e510300000153ba00000000';
      const prevFundTx = prova.Transaction.fromHex(prevFundTxHex);

      const tx = prova.Transaction.fromHex(txHex);

      const builder = prova.TransactionBuilder.fromTransaction(tx, prova.networks.rmg);
      builder.addFundDestructionOutput(2000);

      const outputScript = builder.tx.outs[0].script;
      // sign 0 input and use value 0 (using script from 0th output (incorrect technically))
      builder.signWithTx(0, privateKey, prevAdminTx);

      builder.signWithTx(1, wspPrivKey, prevFundTx);

      console.log('HEX OF SIGNED', builder.buildIncomplete().toHex());
    });

    it('should parse fully signed tx', () => {
      const txHex = '0100000001a90410eca88f858aa6b639980d67fb19549f87ce8b2b4aae4cfaeb426e679be6000000006a21025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1473044022008ab745f9aaf9be937ab2575040fdefccaa19149587c436264dffb072018a73a0220476971acfa84be890a4064baccefbb2d45e328e2079a3a3a447264212cfbe35501ffffffff0200000000000000000200bb0000000000000000246a2201037334a4e8aea91bce5e48d75cdd2852c31b77ab9a2549bebc0be3e3f5116e53c800000000';
      const tx = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(tx);
      console.log('here');
    });
  });

});
