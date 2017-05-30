const bitcoin = require('bitcoinjs-lib');
const crypto = require('crypto');
const ecurve = require('ecurve');
const BigInteger = require('bigi');
const NETWORKS = require('./networks');
const secp256k1 = ecurve.getCurveByName('secp256k1');
const typeforce = require('typeforce');
const types = require('./types');

const ECPair = function ECPair(d, Q, options = {}) {
  try {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }, options);
  } catch (e) {
    throw new Error(e.message);
  }

  if (d) {
    if (d.signum() <= 0) {
      throw new Error('Private key must be greater than 0');
    }
    if (d.compareTo(secp256k1.n) >= 0) {
      throw new Error('Private key must be less than the curve order');
    }
    if (Q) {
      throw new TypeError('Unexpected publicKey parameter');
    }

    this.d = d;
  } else {
    try {
      typeforce(types.ECPoint, Q);
    } catch (e) {
      throw new Error(e.message);
    }

    this.__Q = Q;
  }

  this.compressed = options.compressed === undefined ? true : options.compressed;
  this.network = options.network || NETWORKS.bitcoin;
};

ECPair.prototype = bitcoin.ECPair.prototype;

ECPair.fromPublicKeyBuffer = function(buffer, network) {
  const Q = ecurve.Point.decodeFrom(secp256k1, buffer);

  return new ECPair(null, Q, {
    compressed: Q.compressed,
    network: network
  });
};

ECPair.fromPrivateKeyBuffer = function(buffer, network) {
  try {
    typeforce(typeforce.BufferN(32), buffer);
  } catch (e) {
    throw new Error(e.message);
  }
  const d = BigInteger.fromBuffer(buffer);

  if (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0) {
    throw new Error('bad private key buffer');
  }

  return new ECPair(d, null, { network: network });
};

ECPair.makeRandom = function(network) {
  const privateKeyBuffer = crypto.randomBytes(32);
  return this.fromPrivateKeyBuffer(privateKeyBuffer, network)
};

ECPair.prototype.getPrivateKeyBuffer = function() {
  if (!this.d) {
    throw new Error('private key unknown');
  }
  const bigIntBuffer = this.d.toBuffer();
  if (bigIntBuffer.length > 32) {
    throw new Error('private key size exceeds 32 bytes');
  }
  if (bigIntBuffer.length === 32) {
    return bigIntBuffer;
  }
  const buffer = Buffer.alloc(32);
  bigIntBuffer.copy(buffer, buffer.length - bigIntBuffer.length, 0, bigIntBuffer.length);
  return buffer;
};

module.exports = ECPair;
