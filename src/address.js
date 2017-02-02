const bitcoin = require('bitcoinjs-lib');
const bs58check = require('bs58check');
const bscript = require('./script');
const networks = require('./networks');
const OPS = require('bitcoin-ops');
const ECPair = require('./ecPair');
const HDNode = require('./hdNode');
const typeforce = require('typeforce');
const types = require('./types');

const PROVA_ENCODED_PAYLOAD_LENGTH = 29;
const PROVA_RAW_PAYLOAD_LENGTH = 28;

const fromBase58CheckAztec = (address) => {
  const payload = bs58check.decode(address);
  if (payload.length < PROVA_ENCODED_PAYLOAD_LENGTH) {
    throw new TypeError(address + ' is too short');
  }
  if (payload.length > PROVA_ENCODED_PAYLOAD_LENGTH) {
    throw new TypeError(address + ' is too long');
  }

  const version = payload[0];
  const hash = payload.slice(1);

  return { hash, version };
};

const toBase58CheckAztec = (hash, version) => {
  const payload = new Buffer(PROVA_ENCODED_PAYLOAD_LENGTH);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);

  return bs58check.encode(payload);
};

/**
 *
 * @param publicKey
 * @param keyID1
 * @param keyID2
 * @param network
 * @constructor
 */
const Address = function(publicKey, keyID1, keyID2, network) {
  // store the preferred network for outputs
  this.network = network || networks.rmg;

  if (publicKey) {
    // take the public key and construct ECPair object
    this.setPublicKey(publicKey);
  }

  // store the cosigner key ids
  this.keyID1 = keyID1;
  this.keyID2 = keyID2;
};

Address.fromBase58 = function(base58) {
  const components = fromBase58CheckAztec(base58);

  let network;
  const version = components.version;
  if (version == networks.rmg.rmg) {
    network = networks.rmg;
  } else if (version == networks.rmgTest.rmg) {
    network = networks.rmgTest;
  }

  return Address.fromBuffer(components.hash, network);
};

Address.validateBase58 = function(base58, network) {
  network = network || networks.rmg;
  let components;
  try {
    components = fromBase58CheckAztec(base58);
  } catch (e) {
    return false;
  }
  const buffer = components.hash;
  const version = components.version;
  if (version !== network.rmg) {
    // invalid network
    return false;
  }
  if (buffer.length != PROVA_RAW_PAYLOAD_LENGTH) {
    return false;
  }
  return true;
};

Address.fromScript = function(script, network) {
  const components = bscript.decompile(script);
  const keyHash = components[1];
  const keyID1 = bscript.decodeNumber(components[2]);
  const keyID2 = bscript.decodeNumber(components[3]);

  const address = new Address(null, keyID1, keyID2, network);
  address.setPublicKeyHash(keyHash);
  return address;
};

Address.prototype.toScript = function() {
  const components = [
    OPS.OP_2,
    this.publicKeyHash,
    bscript.encodeNumber(this.keyID1),
    bscript.encodeNumber(this.keyID2),
    OPS.OP_3,
    186 // OP_CHECK_SAFE_MULTISIG
  ];
  return bscript.compile(components);
};

Address.fromBuffer = function(buffer, network) {

  const keyHash = buffer.slice(0, 20);
  const keyID1 = buffer.readUInt32LE(20);
  const keyID2 = buffer.readUInt32LE(24);

  const address = new Address(null, keyID1, keyID2, network);
  address.setPublicKeyHash(keyHash);
  return address;

};

Address.prototype.setPublicKey = function(publicKey) {

  if (Buffer.isBuffer(publicKey)) {
    this.publicKey = ECPair.fromPublicKeyBuffer(publicKey);
  } else if (publicKey instanceof HDNode) {
    return this.setPublicKey(publicKey.getPublicKeyBuffer());
  } else if (publicKey.startsWith('xpub') || publicKey.startsWith('xprv')) {
    const hdNode = HDNode.fromBase58(publicKey, this.network);
    return this.setPublicKey(hdNode.getPublicKeyBuffer());
  }

  // calculate the public key hash
  const encodedPublicKey = this.publicKey.__Q.getEncoded(true);
  this.publicKeyHash = bitcoin.crypto.hash160(encodedPublicKey);
};

Address.prototype.setPublicKeyHash = function(publicKeyHash) {
  this.publicKey = null;
  this.publicKeyHash = publicKeyHash;
};

Address.prototype.toBuffer = function() {
  const inputBuffer = new Buffer(PROVA_RAW_PAYLOAD_LENGTH); // keyID is 4, and key hash is 20
  inputBuffer.fill(0); // initialize it with all zeroes
  this.publicKeyHash.copy(inputBuffer, 0);
  inputBuffer.writeUInt32LE(this.keyID1, 20);
  inputBuffer.writeUInt32LE(this.keyID2, 24);
  return inputBuffer;
};

/**
 *
 * @param network which network to use
 */
Address.prototype.toString = function(network) {
  network = network || this.network;

  const inputBuffer = this.toBuffer();
  return toBase58CheckAztec(inputBuffer, network.rmg);
};

module.exports = Address;
