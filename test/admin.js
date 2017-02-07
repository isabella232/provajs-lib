const assert = require('assert');
const prova = require('../index');
const script = require('../src/script');

describe('Admin', function () {
  describe('Funds Issuing Keys', function() {
    it('add issuing key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22bd025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.ROOT.ISSUANCE_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.ROOT.ISSUANCE_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.ROOT.PROVISIONING_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.ROOT.PROVISIONING_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.PROVISIONING.VALIDATOR_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.PROVISIONING.VALIDATOR_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });
  });

  describe('Account Service Provider Keys', function(){
    it('add ASP key', function() {
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000251bb0000000000000000286a26c3025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf10000010000000000';
      const transaction = prova.Transaction.fromHex(txHex);
      const builder = prova.TransactionBuilder.fromTransaction(transaction);

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.ADD_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.PROVISIONING.ACCOUNT_SERVICE_PROVIDER_KEY;
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

      const operation = prova.TransactionBuilder.ADMIN.OPERATIONS.REVOKE_KEY;
      const keyType = prova.TransactionBuilder.ADMIN.KEY_TYPES.PROVISIONING.ACCOUNT_SERVICE_PROVIDER_KEY;
      const privateKey = prova.ECPair.fromPrivateKeyBuffer(Buffer.from('eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694', 'hex'));
      builder.addKeyUpdateOutput(operation, keyType, privateKey, 65536);

      const originalOutputScript = builder.tx.outs[1].script;
      const addedOutputScript = builder.tx.outs[2].script;
      assert.strictEqual(addedOutputScript.toString('hex'), originalOutputScript.toString('hex'));
    });
  });

});
