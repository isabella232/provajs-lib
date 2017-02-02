module.exports = {
  rmg: {
    messagePrefix: '\x18RMG Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    rmg: 0x33, // starts with G
    wif: 0x80
  },
  rmgTest: {
    messagePrefix: '\x18RMG Test Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    rmg: 0x58, // starts with T
    wif: 0x80
  }
};
