/*
lamport adapted from:

https://en.m.wikipedia.org/wiki/Lamport_signature

NOTE: JavaScript has no 64-bit unsigned integer datatype, 
so we represent them as [uInt32Lo, uInt32Hi]
*/

var 
  utils = require("./utils"),
  keccak = require("keccak-p-js"),
  k256 = keccak.mode("SHA-3-256"),
  /*  
    private key size = 256 pairs of 256 bit numbers
    2 * 256 * 256 / 8, size in bytes = 16kb
  */
  PRIVATE_KEY_WIDTH = 2,
  PRIVATE_KEY_DEPTH = 256,
  PRIVATE_KEY_SIZE_IN_BITS = 256,
  PRIVATE_KEY_SIZE_IN_BYTES = 32,
  PRIVATE_KEY_TOTAL_SIZE_BYTES = 16384,
  PRIVATE_KEY_NUM_INT32 = 512,
  PRIVATE_KEY_NUM_INT64 = 256,
  STR_DOUBLE_ZERO = "00",
  EXPECTED_LENGTH = STR_DOUBLE_ZERO.length,
  HEX_TO_BINARY = {
    '0': [0,0,0,0],
    '1': [0,0,0,1],
    '2': [0,0,1,0],
    '3': [0,0,1,1],
    '4': [0,1,0,0],
    '5': [0,1,0,1],
    '6': [0,1,1,0],
    '7': [0,1,1,1],
    '8': [1,0,0,0],
    '9': [1,0,0,1],
    'a': [1,0,1,0],
    'b': [1,0,1,1],
    'c': [1,1,0,0],
    'd': [1,1,0,1],
    'e': [1,1,1,0],
    'f': [1,1,1,1]
  },
  HEX_BITS = HEX_TO_BINARY['0'].length,
  HEX_BASE = 16,
  lamport = {
    "CONST": {
      "PRIVATE_KEY_WIDTH": PRIVATE_KEY_WIDTH,
      "PRIVATE_KEY_DEPTH": PRIVATE_KEY_DEPTH,
      "PRIVATE_KEY_SIZE_IN_BITS": PRIVATE_KEY_SIZE_IN_BITS,
      "PRIVATE_KEY_SIZE_IN_BYTES": PRIVATE_KEY_SIZE_IN_BYTES,
      "PRIVATE_KEY_TOTAL_SIZE_BYTES": PRIVATE_KEY_TOTAL_SIZE_BYTES,
      "PRIVATE_KEY_NUM_INT32": PRIVATE_KEY_NUM_INT32,
      "PRIVATE_KEY_NUM_INT64": PRIVATE_KEY_NUM_INT64
    },
    "create_private_key": function(key_width, key_depth, key_size) {
      var
        width = key_width || PRIVATE_KEY_WIDTH,
        depth = key_depth || PRIVATE_KEY_DEPTH,
        size = key_size || PRIVATE_KEY_SIZE_IN_BYTES,
        total_size = width * depth * size,
        all_bytes = utils.random.bytes(total_size),
        private_key_pairs = [],
        offset = 0,
        pair, bytes,
        tmp, len,
        x,y,z;
      for (y=0; y<depth; y++) {
        pair = [];
        for (x=0; x<width; x++) {
          bytes = [];
          for (z=0; z<size; z++) {
            tmp = all_bytes[offset++].toString(HEX_BASE);
            len = tmp.length;
            bytes.push(
              len === EXPECTED_LENGTH
                ? tmp 
                : [STR_DOUBLE_ZERO.substr(len), tmp].join('')
            )
          }
          pair.push(bytes.join(''));
        }
        private_key_pairs.push(pair);
      }
      return private_key_pairs;
    },
    "create_public_key": function(private_key) {
      var
        depth = private_key.length,
        width = private_key[0].length,
        public_key = [],
        keys,
        x,y,z;
      for (y=0; y<depth; y++) {
        keys = [];
        for (x=0; x<width; x++) {
          keys.push(
            k256.init().update(
              private_key[y][x]
            ).digest()
          );
        }
        public_key.push(keys);
      }
      return public_key;
    },
    "sign_message": function(message, private_key) {
      var 
        hash = k256.init().update(
          message
        ).digest().split(''),
        len = hash.length,
        result = [],
        hex, bin, bit,
        x,y,z;
      for (z=0; z<len; z++) {
        y = z * HEX_BITS;
        hex = hash[z];
        bin = HEX_TO_BINARY[hex];
        for (x=0; x<HEX_BITS; x++) {
          bit = bin[x];
          result.push(
            private_key[y + x][bit]
          );
        }
      }
      return result;
    },
    "verify_signature": function(message, signature, public_key) {
      var
        hash = k256.init().update(
          message
        ).digest().split(''),
        hash_length = hash.length,
        signature_length = signature.length,
        result = (hash_length === (signature_length / HEX_BITS)),
        idx = -1,
        hex, bin, bit, sig, pub, match,
        x,y,z;
      while (result && ++idx < hash_length) {
        y = idx * HEX_BITS;
        hex = hash[idx];
        bin = HEX_TO_BINARY[hex];
        for (x=0; x<HEX_BITS; x++) {
          bit = bin[x];
          sig = signature[y + x];
          match = k256.init().update(sig).digest();
          pub = public_key[y + x][bit];
          if (pub !== match) {
            result = false;
            break;
          }
        }
      }
      return result;
    }
  };

// make module visible
module.exports = lamport;
