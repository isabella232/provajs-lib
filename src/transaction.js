const bitcoin = require('bitcoinjs-lib');
const typeforce = require('typeforce');
const types = require('./types');
const varuint = require('varuint-bitcoin');

const ZERO = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex');

const Transaction = bitcoin.Transaction;

const varSliceSize = (someScript, __isStripped) => {
  let length = someScript.length;
  if (__isStripped) {
    length = 0;
  }
  return varuint.encodingLength(length) + length;
};

const verifuint = (value, max) => {
  if (typeof value !== 'number') {
    throw new Error('cannot write a non-number as a number');
  }
  if (value < 0) {
    throw new Error('specified a negative value for writing an unsigned value');
  }
  if (value > max) {
    throw new Error('RangeError: value out of range');
  }
  if (Math.floor(value) !== value) {
    throw new Error('value has a fractional component');
  }
};

const bufferWriteUInt64LE = (buffer, value, offset) => {
  verifuint(value, 0x001fffffffffffff);

  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
};

const bufferWriteVarInt = (buffer, number, offset) => {
  varuint.encode(number, buffer, offset);
  return varuint.encode.bytes;
};

Transaction.prototype.getHash = function() {
  return bitcoin.crypto.hash256(this.__toBuffer(undefined, undefined, false, true))
};

Transaction.prototype.__byteLength = function(__allowWitness, __isStripped) {
  const hasWitnesses = __allowWitness && this.hasWitnesses();

  let byteLength = 8;

  if (hasWitnesses) {
    byteLength += 2;
    byteLength += this.ins.reduce((sum, input) => { return sum + vectorSize(input.witness); }, 0);
  }

  byteLength += varuint.encodingLength(this.ins.length);
  byteLength += varuint.encodingLength(this.outs.length);
  byteLength += this.ins.reduce((sum, input) => {
    return sum + 40 + varSliceSize(input.script, __isStripped);
  }, 0);
  byteLength += this.outs.reduce((sum, output) => {
    return sum + 8 + varSliceSize(output.script);
  }, 0);

  return byteLength;
};

Transaction.prototype.__toBuffer = function(buffer, initialOffset, __allowWitness, __isStripped) {
  if (!buffer) buffer = new Buffer(this.__byteLength(__allowWitness, __isStripped));

  let offset = initialOffset || 0;

  const writeSlice = (slice) => { offset += slice.copy(buffer, offset); };

  const writeUInt8 = (i) => { offset = buffer.writeUInt8(i, offset); };

  const writeUInt32 = (i) => { offset = buffer.writeUInt32LE(i, offset); };

  const writeInt32 = (i) => { offset = buffer.writeInt32LE(i, offset); };

  const writeUInt64 = (i) => { offset = bufferWriteUInt64LE(buffer, i, offset); };

  const writeVarInt = (i) => { offset += bufferWriteVarInt(buffer, i, offset); };

  const writeVarSlice = (slice) => {
    writeVarInt(slice.length);
    writeSlice(slice);
  };

  const writeVector = (vector) => {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  };

  writeInt32(this.version);

  const hasWitnesses = __allowWitness && this.hasWitnesses();

  if (hasWitnesses) {
    writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
    writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
  }

  writeVarInt(this.ins.length);

  this.ins.forEach((txIn) => {
    writeSlice(txIn.hash);
    writeUInt32(txIn.index);
    if (__isStripped) {
      writeVarSlice(new Buffer(0));
    } else {
      writeVarSlice(txIn.script);
    }
    writeUInt32(txIn.sequence);
  });

  writeVarInt(this.outs.length);
  this.outs.forEach((txOut) => {
    if (!txOut.valueBuffer) {
      writeUInt64(txOut.value);
    } else {
      writeSlice(txOut.valueBuffer);
    }

    writeVarSlice(txOut.script);
  });

  if (hasWitnesses) {
    this.ins.forEach((input) => {
      writeVector(input.witness);
    });
  }

  writeUInt32(this.locktime);

  // avoid slicing unless necessary
  if (initialOffset !== undefined) return buffer.slice(initialOffset, offset);
  return buffer;
};

Transaction.prototype.hashForWitnessV0 = function(inIndex, prevOutScript, value, hashType) {
  typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments);

  let tbuffer, toffset;
  const writeSlice = (slice) => { toffset += slice.copy(tbuffer, toffset); };
  const writeUInt32 = (i) => { toffset = tbuffer.writeUInt32LE(i, toffset); };
  const writeUInt64 = (i) => { toffset = bufferWriteUInt64LE(tbuffer, i, toffset); };
  const writeVarInt = (i) => { toffset += bufferWriteVarInt(tbuffer, i, toffset); };
  const writeVarSlice = (slice) => {
    writeVarInt(slice.length);
    writeSlice(slice);
  };

  let hashOutputs = ZERO;
  let hashPrevouts = ZERO;
  let hashSequence = ZERO;

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
    tbuffer = new Buffer(36 * this.ins.length);
    toffset = 0;

    this.ins.forEach((txIn) => {
      writeSlice(txIn.hash);
      writeUInt32(txIn.index);
    });

    hashPrevouts = bitcoin.crypto.hash256(tbuffer);
  }

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
  (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
  (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    tbuffer = new Buffer(4 * this.ins.length);
    toffset = 0;

    this.ins.forEach((txIn) => {
      writeUInt32(txIn.sequence);
    });

    hashSequence = bitcoin.crypto.hash256(tbuffer);
  }

  if ((hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
  (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    const txOutsSize = this.outs.reduce((sum, output) => {
      return sum + 8 + varSliceSize(output.script);
    }, 0);

    tbuffer = new Buffer(txOutsSize);
    toffset = 0;

    this.outs.forEach((out) => {
      writeUInt64(out.value);
      writeVarSlice(out.script);
    });

    hashOutputs = bitcoin.crypto.hash256(tbuffer);
  } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE && inIndex < this.outs.length) {
    const output = this.outs[inIndex];

    tbuffer = new Buffer(8 + varSliceSize(output.script));
    toffset = 0;
    writeUInt64(output.value);
    writeVarSlice(output.script);

    hashOutputs = bitcoin.crypto.hash256(tbuffer);
  }

  // tbuffer = new Buffer(156 + varSliceSize(prevOutScript));
  tbuffer = new Buffer(156);
  toffset = 0;

  const input = this.ins[inIndex];
  writeUInt32(this.version);
  writeSlice(hashPrevouts);
  writeSlice(hashSequence);
  writeSlice(input.hash);
  writeUInt32(input.index);

  // writeVarSlice(prevOutScript);

  writeUInt64(value);
  writeUInt32(input.sequence);
  writeSlice(hashOutputs);
  writeUInt32(this.locktime);
  writeUInt32(hashType);
  return bitcoin.crypto.hash256(tbuffer);
};

module.exports = Transaction;
