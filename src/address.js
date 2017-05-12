const bitcoin = require('bitcoinjs-lib');
const bs58check = require('bs58check');
const bscript = require('./script');
const networks = require('./networks');
const OPS = require('./ops');
const ECPair = require('./ecPair');
const HDNode = require('./hdNode');

const MIN_ENCODED_PAYLOAD_LENGTH = 29;
const MIN_KEYIDS = 2;
const MAX_KEYIDS = 19;
const KEYHASH_SIZE = 20;
const KEYID_SIZE = 4;

const fromBase58CheckAztec = (address) => {
  const payload = bs58check.decode(address);
  if (payload.length < MIN_ENCODED_PAYLOAD_LENGTH) {
    throw new TypeError(address + ' is too short');
  }

  const version = payload[0];
  const buffer = payload.slice(1);

  return { buffer, version };
};

const toBase58CheckAztec = (buf, version) => {
  const payload = new Buffer(1 + buf.length);
  payload.writeUInt8(version, 0);
  buf.copy(payload, 1);

  return bs58check.encode(payload);
};

/**
 * This class represents a standard Aztec address which must represent a script of the form:
 *   n-1 <keyhash> <n-1 keyids> n OP_CHECKSAFEMULTISIG
 */
class Address {
  /**
   *
   * @param publicKey
   * @param keyIDs
   * @param network
   * @constructor
   */
  constructor(publicKey, keyIDs, network = networks.rmg) {
    // store the preferred network for outputs
    this.network = network;

    if (publicKey) {
      // take the public key and construct ECPair object
      this.setPublicKey(publicKey);
    }

    if (!keyIDs || keyIDs.length < 2 || keyIDs.length > 19) {
      throw new Error('invalid number of key ids');
    }

    keyIDs.forEach(function(keyID) {
      if (typeof(keyID) !== 'number' || keyID < 0 || keyID > Math.pow(2,31)) {
        throw new Error('invalid keyid');
      }
    });

    // store the cosigner key ids
    this.keyIDs = keyIDs.slice(0);
  }

  static fromBase58(base58) {
    const components = fromBase58CheckAztec(base58);

    let network;
    const version = components.version;
    if (version == networks.rmg.rmg) {
      network = networks.rmg;
    } else if (version == networks.rmgTest.rmg) {
      network = networks.rmgTest;
    }

    return Address.fromBuffer(components.buffer, network);
  }

  static validateBase58(base58, network=networks.rmg) {
    try {
      const addr = Address.fromBase58(base58, network);
      return addr.network === network;
    } catch (e) {
      return false;
    }
  }

  static fromScript(script, network) {
    const components = bscript.decompile(script);
    const len = components.length;
    if (len < 6) {
      throw new Error('invalid script format');
    }
    const m = bscript.decodeNumber(components[0]);
    if (!m || m < MIN_KEYIDS || m > MAX_KEYIDS) {
      throw new Error('invalid m value in script');
    }
    const keyHash = components[1];
    const keyIDCount = components.length - 4; /* subtract out m, keyhash, n and OP_CHECKSAFEMULTISIG */
    const op = components[len-1];
    if (op !== OPS.OP_CHECKSAFEMULTISIG) {
      throw new Error('Expected OP_CHECKSAFEMULTISIG');
    }
    const keyIDs = components.slice(2, 2+keyIDCount).map(bscript.decodeNumber);
    const n = bscript.decodeNumber(components[len-2]);
    if (n !== m+1) {
      throw new Error('n must be equal to m+1');
    }
    if (n !== keyIDCount + 1) {
      throw new Error('n inconsistent with number of keys');
    }

    const address = new Address(null, keyIDs, network);
    address.setPublicKeyHash(keyHash);
    return address;
  }

  static fromBuffer(buffer, network) {
    const len = buffer.length;
    const keyIDCount = (len - KEYHASH_SIZE) / KEYID_SIZE;
    if (Math.floor(keyIDCount) !== keyIDCount) {
      throw new Error('unexpected buffer length: ' + len);
    }
    const keyHash = buffer.slice(0, KEYHASH_SIZE);
    let pos = KEYHASH_SIZE;
    const keyIDs = [];
    for (let i=0; i < keyIDCount; i++) {
      keyIDs.push(buffer.readUInt32LE(pos));
      pos += KEYID_SIZE;
    }

    const address = new Address(null, keyIDs, network);
    address.setPublicKeyHash(keyHash);
    return address;
  }

  totalKeys() {
    return 1 + this.keyIDs.length;
  }

  signaturesNeeded() {
    return this.totalKeys() - 1;
  }

  toScript() {
    const components = [
      bscript.encodeNumber(this.signaturesNeeded()),
      this.publicKeyHash
    ]
    .concat(this.keyIDs.map(bscript.encodeNumber))
    .concat([
      bscript.encodeNumber(this.totalKeys()),
      OPS.OP_CHECKSAFEMULTISIG
    ]);
    return bscript.compile(components);
  }

  setPublicKey(publicKey) {
    if (publicKey instanceof ECPair) {
      this.publicKey = publicKey;
    } else if (Buffer.isBuffer(publicKey)) {
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
  }

  setPublicKeyHash(publicKeyHash) {
    this.publicKey = null;
    this.publicKeyHash = publicKeyHash;
  }

  toBuffer() {
    const inputBuffer = new Buffer(KEYHASH_SIZE + this.keyIDs.length * KEYID_SIZE);
    inputBuffer.fill(0); // initialize it with all zeroes
    this.publicKeyHash.copy(inputBuffer, 0);
    let pos = KEYHASH_SIZE;
    this.keyIDs.forEach(function(keyID) {
      inputBuffer.writeUInt32LE(keyID, pos);
      pos += KEYID_SIZE;
    });
    return inputBuffer;
  }

  /**
   *
   * @param network which network to use
   */
  toString(network = this.network) {
    const inputBuffer = this.toBuffer();
    return toBase58CheckAztec(inputBuffer, network.rmg);
  }

}

module.exports = Address;
