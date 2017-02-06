const Address = require('./Address');
const bitcoin = require('bitcoinjs-lib');
const Transaction = require('./Transaction');

const TransactionBuilder = bitcoin.TransactionBuilder;

const expandInput = (scriptSig) => {
  const scriptSigChunks = bitcoin.script.decompile(scriptSig);

  const pubKeys = scriptSigChunks.filter((_, index) => { return index % 2 === 0; });
  const signatures = scriptSigChunks.filter((_, index) => { return index % 2 === 1; });

  return {
    pubKeys: pubKeys,
    signatures: signatures
  };
};

const buildInput = (input) => {
  const interlace = [];
  input.pubKeys.forEach((pubKey, index) => {
    interlace.push(pubKey, input.signatures[index]);
  });

  const scriptType = bitcoin.script.types.P2WSH;
  const script = bitcoin.script.compile(interlace);
  const witness = [];

  return {
    type: scriptType,
    script: script,
    witness: witness
  }
};

/**
 * Admin Outputs can be either thread continuation outputs, or operation outputs
 * Creates an output delineating the thread
 * Operation outputs are broken down as follows:
 * - Issue and revoke keys (Root thread)
 *   - Provisioning keys (can issue and revoke validator and ASP keys)
 *   - Issuing keys (can issue and destroy funds)
 * - Provision non-root keys (Provisioning thread)
 *   - Validator keys (like mining)
 *   - Account Service Provider keys
 * - Issue funds (Issuing thread)
 */
TransactionBuilder.prototype.addAdminThreadOutput = function(thread) {

};

/**
 * Auto-infers the thread based on keyType
 * @param operation (whether it's to provision or to revoke)
 * @param keyType
 * @param keyID
 * @param publicKey
 */
TransactionBuilder.prototype.addKeyUpdateOutput = function(operation, keyType, keyID, publicKey) {

};

TransactionBuilder.prototype.addFundIssuanceOutput = function(destination, amount) {

};

TransactionBuilder.prototype.addFundDestructionOutput = function(amount) {

};


TransactionBuilder.prototype.__addInputUnsafe = function(txHash, vout, options) {
  if (Transaction.isCoinbaseHash(txHash)) {
    throw new Error('coinbase inputs not supported')
  }

  const prevTxOut = txHash.toString('hex') + ':' + vout;
  if (this.prevTxMap[prevTxOut] !== undefined) {
    throw new Error('Duplicate TxOut: ' + prevTxOut);
  }

  let input = {};

  // derive what we can from the scriptSig
  if (options.script !== undefined) {
    input = expandInput(options.script, options.witness);
  }

  // if an input value was given, retain it
  if (options.value !== undefined) {
    input.value = options.value;
  }

  // derive what we can from the previous transactions output script
  if (!input.prevOutScript && options.prevOutScript) {
    let prevOutType;

    if (!input.pubKeys && !input.signatures) {
      const expanded = expandOutput(options.prevOutScript);

      if (expanded.pubKeys) {
        input.pubKeys = expanded.pubKeys;
        input.signatures = expanded.signatures;
      }

      prevOutType = expanded.scriptType;
    }

    input.prevOutScript = options.prevOutScript;
    input.prevOutType = prevOutType || bitcoin.script.classifyOutput(options.prevOutScript);
  }

  input.pubKeys = input.pubKeys || [];
  input.signatures = input.signatures || [];

  const vin = this.tx.addInput(txHash, vout, options.sequence, options.scriptSig);
  this.inputs[vin] = input;
  this.prevTxMap[prevTxOut] = vin;

  return vin;
};

TransactionBuilder.prototype.addOutput = function(scriptPubKey, value) {
  if (!this.__canModifyOutputs()) {
    throw new Error('No, this would invalidate signatures')
  }

  // Attempt to get a script if it's a base58 address string
  if (typeof scriptPubKey === 'string') {
    scriptPubKey = Address.fromBase58(scriptPubKey).toScript();
  } else if (scriptPubKey instanceof Address) {
    scriptPubKey = scriptPubKey.toScript();
  }

  return this.tx.addOutput(scriptPubKey, value)
};

TransactionBuilder.prototype.signWithTx = function(vin, keyPair, prevOutTx) {
  // ready to sign
  const prevOut = prevOutTx.outs[this.tx.ins[vin].index];
  const hashScript = prevOut.script;
  const witnessValue = prevOut.value;

  return this.sign(vin, keyPair, hashScript, witnessValue);
};

TransactionBuilder.prototype.sign = function(vin, keyPair, redeemScript, redeemValue) {
  if (keyPair.network !== this.network) {
    throw new Error('Inconsistent network');
  }
  if (!this.inputs[vin]) {
    throw new Error('No input at index: ' + vin);
  }
  const hashType = Transaction.SIGHASH_ALL;

  const input = this.inputs[vin];

  const kpPubKey = keyPair.getPublicKeyBuffer();

  const signatureHash = this.tx.hashForWitnessV0(vin, redeemScript, redeemValue, hashType);

  const signature = keyPair.sign(signatureHash).toScriptSignature(hashType);
  input.pubKeys.push(kpPubKey);
  input.signatures.push(signature);
};

TransactionBuilder.prototype.__build = function(allowIncomplete) {
  if (!allowIncomplete) {
    if (!this.tx.ins.length) {
      throw new Error('Transaction has no inputs');
    }
    if (!this.tx.outs.length) {
      throw new Error('Transaction has no outputs');
    }
  }

  const tx = this.tx.clone();
  // Create script signatures from inputs
  this.inputs.forEach((input, i) => {
    const isIncompleteAztec = ((input.pubKeys.length !== input.signatures.length) || input.signatures.length < 2);
    if (isIncompleteAztec && !allowIncomplete) {
      throw new Error('Transaction is not complete');
    }
    const result = buildInput(input, allowIncomplete);

    tx.setInputScript(i, result.script);
    tx.setWitness(i, result.witness);
  });

  if (!allowIncomplete) {
    // do not rely on this, its merely a last resort
    if (this.__overMaximumFees(tx.byteLength())) {
      throw new Error('Transaction has absurd fees');
    }
  }

  return tx;
};

module.exports = TransactionBuilder;
