const bitcoin = require('bitcoinjs-lib');
const ecurve = require('ecurve');
const BigInteger = require('bigi');
const NETWORKS = require('./networks');
const secp256k1 = ecurve.getCurveByName('secp256k1');
const typeforce = require('typeforce');
const types = require('./types');

const ECPair = function ECPair(d, Q, options = {}) {
  typeforce({
    compressed: types.maybe(types.Boolean),
    network: types.maybe(types.Network)
  }, options);

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
    typeforce(types.ECPoint, Q);

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
  typeforce(typeforce.BufferN(32), buffer);
  const d = BigInteger.fromBuffer(buffer);

  if (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0) {
    throw new Error('bad private key buffer');
  }

  return new ECPair(d, null, { network: network });
};

ECPair.prototype.getPrivateKeyBuffer = function() {
  if (!this.d) {
    throw new Error('private key unknown');
  }
  return this.d.toBuffer();
};

module.exports = ECPair;
