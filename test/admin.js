const assert = require('assert');
const prova = require('../index');

describe('Admin', function () {
  describe('Funds Issuing Keys', function() {
    it('add issuing key', function() {
      // this transaction has to be signed by two root keys
      // this transaction follows the root thread
      // structure:
      // 1 input, 1 output for thread continuation
      // non-spendable outputs for operations
      const txHex = '0100000001b0c40ddce1f8e15390517dfe848a7db1c16fd77ff0fa599dba75cb6a8f6fb1a90000000000ffffffff0200000000000000000200bb0000000000000000246a22bd025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf100000000';
      const transaction = prova.Transaction.fromHex(txHex);
    });
  });
});
