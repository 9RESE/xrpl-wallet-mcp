#!/usr/bin/env node
import { __commonJS, __require, AuditEventTypeSchema, TransactionTypeSchema, __toESM, InputSchemas } from './chunk-UHUYJFUT.js';
export { AgentWalletPolicySchema, ApprovalTierSchema, AuditEventTypeSchema, AuditLogEntrySchema, DecodedTransactionSchema, DestinationModeSchema, DropsAmountOptionalZeroSchema, DropsAmountSchema, ErrorCodeSchema, ErrorResponseSchema, EscrowReferenceSchema, HexStringRawSchema, HexStringSchema, InputSchemas, LedgerIndexSchema, LimitStatusSchema, NetworkConfigInputSchema, NetworkConfigOutputSchema, NetworkSchema, NotificationEventSchema, OutputSchemas, PaginationMarkerSchema, PolicyDestinationsSchema, PolicyEscalationSchema, PolicyLimitsSchema, PolicyNotificationsSchema, PolicySetInputSchema, PolicySetOutputSchema, PolicyTimeControlsSchema, PolicyTransactionTypesSchema, PolicyViolationSchema, PublicKeySchema, RemainingLimitsSchema, SequenceNumberSchema, SignedTransactionBlobSchema, SignerEntrySchema, TimestampSchema, TransactionHashSchema, TransactionHistoryEntrySchema, TransactionResultSchema, TransactionTypeSchema, TxDecodeInputSchema, TxDecodeOutputSchema, TxSubmitInputSchema, TxSubmitOutputSchema, UnsignedTransactionBlobSchema, WalletBalanceInputSchema, WalletBalanceOutputSchema, WalletCreateInputSchema, WalletCreateOutputSchema, WalletFundInputSchema, WalletFundOutputSchema, WalletHistoryInputSchema, WalletHistoryOutputSchema, WalletIdSchema, WalletListEntrySchema, WalletListInputSchema, WalletListOutputSchema, WalletNameSchema, WalletPolicyCheckInputSchema, WalletPolicyCheckOutputSchema, WalletRotateInputSchema, WalletRotateOutputSchema, WalletSignApprovedOutputSchema, WalletSignInputSchema, WalletSignOutputSchema, WalletSignPendingOutputSchema, WalletSignRejectedOutputSchema, XRPLAddressSchema } from './chunk-UHUYJFUT.js';
import * as crypto from 'crypto';
import { createHmac, createHash, randomUUID } from 'crypto';
import { z } from 'zod';
import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as path2 from 'path';
import { promises } from 'fs';
import * as argon2 from 'argon2';
import { ECDSA, Wallet, Client, decode, encode, multisign, hashes, dropsToXrp as dropsToXrp$1 } from 'xrpl';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// node_modules/@noble/hashes/cryptoNode.js
var require_cryptoNode = __commonJS({
  "node_modules/@noble/hashes/cryptoNode.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.crypto = void 0;
    var nc = __require("crypto");
    exports$1.crypto = nc && typeof nc === "object" && "webcrypto" in nc ? nc.webcrypto : nc && typeof nc === "object" && "randomBytes" in nc ? nc : void 0;
  }
});

// node_modules/@noble/hashes/utils.js
var require_utils = __commonJS({
  "node_modules/@noble/hashes/utils.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.wrapXOFConstructorWithOpts = exports$1.wrapConstructorWithOpts = exports$1.wrapConstructor = exports$1.Hash = exports$1.nextTick = exports$1.swap32IfBE = exports$1.byteSwapIfBE = exports$1.swap8IfBE = exports$1.isLE = void 0;
    exports$1.isBytes = isBytes;
    exports$1.anumber = anumber;
    exports$1.abytes = abytes;
    exports$1.ahash = ahash;
    exports$1.aexists = aexists;
    exports$1.aoutput = aoutput;
    exports$1.u8 = u8;
    exports$1.u32 = u32;
    exports$1.clean = clean;
    exports$1.createView = createView;
    exports$1.rotr = rotr;
    exports$1.rotl = rotl;
    exports$1.byteSwap = byteSwap;
    exports$1.byteSwap32 = byteSwap32;
    exports$1.bytesToHex = bytesToHex;
    exports$1.hexToBytes = hexToBytes;
    exports$1.asyncLoop = asyncLoop;
    exports$1.utf8ToBytes = utf8ToBytes;
    exports$1.bytesToUtf8 = bytesToUtf8;
    exports$1.toBytes = toBytes;
    exports$1.kdfInputToBytes = kdfInputToBytes;
    exports$1.concatBytes = concatBytes;
    exports$1.checkOpts = checkOpts;
    exports$1.createHasher = createHasher;
    exports$1.createOptHasher = createOptHasher;
    exports$1.createXOFer = createXOFer;
    exports$1.randomBytes = randomBytes2;
    var crypto_1 = require_cryptoNode();
    function isBytes(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function anumber(n) {
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("positive integer expected, got " + n);
    }
    function abytes(b, ...lengths) {
      if (!isBytes(b))
        throw new Error("Uint8Array expected");
      if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
    }
    function ahash(h) {
      if (typeof h !== "function" || typeof h.create !== "function")
        throw new Error("Hash should be wrapped by utils.createHasher");
      anumber(h.outputLen);
      anumber(h.blockLen);
    }
    function aexists(instance, checkFinished = true) {
      if (instance.destroyed)
        throw new Error("Hash instance has been destroyed");
      if (checkFinished && instance.finished)
        throw new Error("Hash#digest() has already been called");
    }
    function aoutput(out, instance) {
      abytes(out);
      const min = instance.outputLen;
      if (out.length < min) {
        throw new Error("digestInto() expects output buffer of length at least " + min);
      }
    }
    function u8(arr) {
      return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function u32(arr) {
      return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
    }
    function clean(...arrays) {
      for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
      }
    }
    function createView(arr) {
      return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    }
    function rotr(word, shift) {
      return word << 32 - shift | word >>> shift;
    }
    function rotl(word, shift) {
      return word << shift | word >>> 32 - shift >>> 0;
    }
    exports$1.isLE = (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    function byteSwap(word) {
      return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
    }
    exports$1.swap8IfBE = exports$1.isLE ? (n) => n : (n) => byteSwap(n);
    exports$1.byteSwapIfBE = exports$1.swap8IfBE;
    function byteSwap32(arr) {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
      }
      return arr;
    }
    exports$1.swap32IfBE = exports$1.isLE ? (u) => u : byteSwap32;
    var hasHexBuiltin = /* @__PURE__ */ (() => (
      // @ts-ignore
      typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
    ))();
    var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
    function bytesToHex(bytes) {
      abytes(bytes);
      if (hasHexBuiltin)
        return bytes.toHex();
      let hex = "";
      for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
      }
      return hex;
    }
    var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    function asciiToBase16(ch) {
      if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0;
      if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10);
      if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10);
      return;
    }
    function hexToBytes(hex) {
      if (typeof hex !== "string")
        throw new Error("hex string expected, got " + typeof hex);
      if (hasHexBuiltin)
        return Uint8Array.fromHex(hex);
      const hl = hex.length;
      const al = hl / 2;
      if (hl % 2)
        throw new Error("hex string expected, got unpadded hex of length " + hl);
      const array = new Uint8Array(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0) {
          const char = hex[hi] + hex[hi + 1];
          throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
      }
      return array;
    }
    var nextTick = async () => {
    };
    exports$1.nextTick = nextTick;
    async function asyncLoop(iters, tick, cb) {
      let ts = Date.now();
      for (let i = 0; i < iters; i++) {
        cb(i);
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
          continue;
        await (0, exports$1.nextTick)();
        ts += diff;
      }
    }
    function utf8ToBytes(str) {
      if (typeof str !== "string")
        throw new Error("string expected");
      return new Uint8Array(new TextEncoder().encode(str));
    }
    function bytesToUtf8(bytes) {
      return new TextDecoder().decode(bytes);
    }
    function toBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes(data);
      return data;
    }
    function kdfInputToBytes(data) {
      if (typeof data === "string")
        data = utf8ToBytes(data);
      abytes(data);
      return data;
    }
    function concatBytes(...arrays) {
      let sum = 0;
      for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes(a);
        sum += a.length;
      }
      const res = new Uint8Array(sum);
      for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
      }
      return res;
    }
    function checkOpts(defaults, opts) {
      if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
        throw new Error("options should be object or undefined");
      const merged = Object.assign(defaults, opts);
      return merged;
    }
    var Hash = class {
    };
    exports$1.Hash = Hash;
    function createHasher(hashCons) {
      const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
      const tmp = hashCons();
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = () => hashCons();
      return hashC;
    }
    function createOptHasher(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    function createXOFer(hashCons) {
      const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
      const tmp = hashCons({});
      hashC.outputLen = tmp.outputLen;
      hashC.blockLen = tmp.blockLen;
      hashC.create = (opts) => hashCons(opts);
      return hashC;
    }
    exports$1.wrapConstructor = createHasher;
    exports$1.wrapConstructorWithOpts = createOptHasher;
    exports$1.wrapXOFConstructorWithOpts = createXOFer;
    function randomBytes2(bytesLength = 32) {
      if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === "function") {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
      }
      if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === "function") {
        return Uint8Array.from(crypto_1.crypto.randomBytes(bytesLength));
      }
      throw new Error("crypto.getRandomValues must be defined");
    }
  }
});

// node_modules/@xrplf/isomorphic/dist/utils/shared.js
var require_shared = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/utils/shared.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.equal = exports$1.concat = exports$1.HEX_REGEX = void 0;
    var utils_1 = require_utils();
    exports$1.HEX_REGEX = /^[A-F0-9]*$/iu;
    function concat(views) {
      return (0, utils_1.concatBytes)(...views);
    }
    exports$1.concat = concat;
    function equal(buf1, buf2) {
      if (buf1.byteLength !== buf2.byteLength) {
        return false;
      }
      const dv1 = new Int8Array(buf1);
      const dv2 = new Int8Array(buf2);
      for (let i = 0; i !== buf1.byteLength; i++) {
        if (dv1[i] !== dv2[i]) {
          return false;
        }
      }
      return true;
    }
    exports$1.equal = equal;
  }
});

// node_modules/@xrplf/isomorphic/dist/utils/index.js
var require_utils2 = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/utils/index.js"(exports$1) {
    var __createBinding = exports$1 && exports$1.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __exportStar = exports$1 && exports$1.__exportStar || function(m, exports2) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports2, p)) __createBinding(exports2, m, p);
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.stringToHex = exports$1.hexToString = exports$1.randomBytes = exports$1.hexToBytes = exports$1.bytesToHex = void 0;
    var crypto_1 = __require("crypto");
    var shared_1 = require_shared();
    var OriginalBuffer = /* @__PURE__ */ Symbol("OriginalBuffer");
    function toUint8Array(buffer) {
      const u8Array = new Uint8Array(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
      u8Array[OriginalBuffer] = buffer;
      return u8Array;
    }
    var bytesToHex = (bytes) => {
      const buf = Buffer.from(bytes);
      return buf.toString("hex").toUpperCase();
    };
    exports$1.bytesToHex = bytesToHex;
    var hexToBytes = (hex) => {
      if (!shared_1.HEX_REGEX.test(hex)) {
        throw new Error("Invalid hex string");
      }
      return toUint8Array(Buffer.from(hex, "hex"));
    };
    exports$1.hexToBytes = hexToBytes;
    var randomBytes2 = (size) => {
      return toUint8Array((0, crypto_1.randomBytes)(size));
    };
    exports$1.randomBytes = randomBytes2;
    var hexToString = (hex, encoding = "utf8") => {
      if (!shared_1.HEX_REGEX.test(hex)) {
        throw new Error("Invalid hex string");
      }
      return new TextDecoder(encoding).decode((0, exports$1.hexToBytes)(hex));
    };
    exports$1.hexToString = hexToString;
    var stringToHex = (string) => {
      return (0, exports$1.bytesToHex)(new TextEncoder().encode(string));
    };
    exports$1.stringToHex = stringToHex;
    __exportStar(require_shared(), exports$1);
  }
});

// node_modules/@scure/base/lib/index.js
var require_lib = __commonJS({
  "node_modules/@scure/base/lib/index.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.bytes = exports$1.stringToBytes = exports$1.str = exports$1.bytesToString = exports$1.hex = exports$1.utf8 = exports$1.bech32m = exports$1.bech32 = exports$1.base58check = exports$1.createBase58check = exports$1.base58xmr = exports$1.base58xrp = exports$1.base58flickr = exports$1.base58 = exports$1.base64urlnopad = exports$1.base64url = exports$1.base64nopad = exports$1.base64 = exports$1.base32crockford = exports$1.base32hexnopad = exports$1.base32hex = exports$1.base32nopad = exports$1.base32 = exports$1.base16 = exports$1.utils = void 0;
    function isBytes(a) {
      return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    }
    function abytes(b, ...lengths) {
      if (!isBytes(b))
        throw new Error("Uint8Array expected");
      if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
    }
    function isArrayOf(isString, arr) {
      if (!Array.isArray(arr))
        return false;
      if (arr.length === 0)
        return true;
      if (isString) {
        return arr.every((item) => typeof item === "string");
      } else {
        return arr.every((item) => Number.isSafeInteger(item));
      }
    }
    function afn(input) {
      if (typeof input !== "function")
        throw new Error("function expected");
      return true;
    }
    function astr(label, input) {
      if (typeof input !== "string")
        throw new Error(`${label}: string expected`);
      return true;
    }
    function anumber(n) {
      if (!Number.isSafeInteger(n))
        throw new Error(`invalid integer: ${n}`);
    }
    function aArr(input) {
      if (!Array.isArray(input))
        throw new Error("array expected");
    }
    function astrArr(label, input) {
      if (!isArrayOf(true, input))
        throw new Error(`${label}: array of strings expected`);
    }
    function anumArr(label, input) {
      if (!isArrayOf(false, input))
        throw new Error(`${label}: array of numbers expected`);
    }
    // @__NO_SIDE_EFFECTS__
    function chain(...args) {
      const id = (a) => a;
      const wrap = (a, b) => (c) => a(b(c));
      const encode2 = args.map((x) => x.encode).reduceRight(wrap, id);
      const decode7 = args.map((x) => x.decode).reduce(wrap, id);
      return { encode: encode2, decode: decode7 };
    }
    // @__NO_SIDE_EFFECTS__
    function alphabet(letters) {
      const lettersA = typeof letters === "string" ? letters.split("") : letters;
      const len = lettersA.length;
      astrArr("alphabet", lettersA);
      const indexes = new Map(lettersA.map((l, i) => [l, i]));
      return {
        encode: (digits) => {
          aArr(digits);
          return digits.map((i) => {
            if (!Number.isSafeInteger(i) || i < 0 || i >= len)
              throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
            return lettersA[i];
          });
        },
        decode: (input) => {
          aArr(input);
          return input.map((letter) => {
            astr("alphabet.decode", letter);
            const i = indexes.get(letter);
            if (i === void 0)
              throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
            return i;
          });
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function join3(separator = "") {
      astr("join", separator);
      return {
        encode: (from) => {
          astrArr("join.decode", from);
          return from.join(separator);
        },
        decode: (to) => {
          astr("join.decode", to);
          return to.split(separator);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function padding(bits, chr = "=") {
      anumber(bits);
      astr("padding", chr);
      return {
        encode(data) {
          astrArr("padding.encode", data);
          while (data.length * bits % 8)
            data.push(chr);
          return data;
        },
        decode(input) {
          astrArr("padding.decode", input);
          let end = input.length;
          if (end * bits % 8)
            throw new Error("padding: invalid, string should have whole number of bytes");
          for (; end > 0 && input[end - 1] === chr; end--) {
            const last = end - 1;
            const byte = last * bits;
            if (byte % 8 === 0)
              throw new Error("padding: invalid, string has too much padding");
          }
          return input.slice(0, end);
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function normalize(fn) {
      afn(fn);
      return { encode: (from) => from, decode: (to) => fn(to) };
    }
    function convertRadix(data, from, to) {
      if (from < 2)
        throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
      if (to < 2)
        throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
      aArr(data);
      if (!data.length)
        return [];
      let pos = 0;
      const res = [];
      const digits = Array.from(data, (d) => {
        anumber(d);
        if (d < 0 || d >= from)
          throw new Error(`invalid integer: ${d}`);
        return d;
      });
      const dlen = digits.length;
      while (true) {
        let carry = 0;
        let done = true;
        for (let i = pos; i < dlen; i++) {
          const digit = digits[i];
          const fromCarry = from * carry;
          const digitBase = fromCarry + digit;
          if (!Number.isSafeInteger(digitBase) || fromCarry / from !== carry || digitBase - digit !== fromCarry) {
            throw new Error("convertRadix: carry overflow");
          }
          const div = digitBase / to;
          carry = digitBase % to;
          const rounded = Math.floor(div);
          digits[i] = rounded;
          if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
            throw new Error("convertRadix: carry overflow");
          if (!done)
            continue;
          else if (!rounded)
            pos = i;
          else
            done = false;
        }
        res.push(carry);
        if (done)
          break;
      }
      for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
        res.push(0);
      return res.reverse();
    }
    var gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
    var radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
    var powers = /* @__PURE__ */ (() => {
      let res = [];
      for (let i = 0; i < 40; i++)
        res.push(2 ** i);
      return res;
    })();
    function convertRadix2(data, from, to, padding2) {
      aArr(data);
      if (from <= 0 || from > 32)
        throw new Error(`convertRadix2: wrong from=${from}`);
      if (to <= 0 || to > 32)
        throw new Error(`convertRadix2: wrong to=${to}`);
      if (/* @__PURE__ */ radix2carry(from, to) > 32) {
        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${/* @__PURE__ */ radix2carry(from, to)}`);
      }
      let carry = 0;
      let pos = 0;
      const max = powers[from];
      const mask = powers[to] - 1;
      const res = [];
      for (const n of data) {
        anumber(n);
        if (n >= max)
          throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
        carry = carry << from | n;
        if (pos + from > 32)
          throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
        pos += from;
        for (; pos >= to; pos -= to)
          res.push((carry >> pos - to & mask) >>> 0);
        const pow = powers[pos];
        if (pow === void 0)
          throw new Error("invalid carry");
        carry &= pow - 1;
      }
      carry = carry << to - pos & mask;
      if (!padding2 && pos >= from)
        throw new Error("Excess padding");
      if (!padding2 && carry > 0)
        throw new Error(`Non-zero padding: ${carry}`);
      if (padding2 && pos > 0)
        res.push(carry >>> 0);
      return res;
    }
    // @__NO_SIDE_EFFECTS__
    function radix(num) {
      anumber(num);
      const _256 = 2 ** 8;
      return {
        encode: (bytes) => {
          if (!isBytes(bytes))
            throw new Error("radix.encode input should be Uint8Array");
          return convertRadix(Array.from(bytes), _256, num);
        },
        decode: (digits) => {
          anumArr("radix.decode", digits);
          return Uint8Array.from(convertRadix(digits, num, _256));
        }
      };
    }
    // @__NO_SIDE_EFFECTS__
    function radix2(bits, revPadding = false) {
      anumber(bits);
      if (bits <= 0 || bits > 32)
        throw new Error("radix2: bits should be in (0..32]");
      if (/* @__PURE__ */ radix2carry(8, bits) > 32 || /* @__PURE__ */ radix2carry(bits, 8) > 32)
        throw new Error("radix2: carry overflow");
      return {
        encode: (bytes) => {
          if (!isBytes(bytes))
            throw new Error("radix2.encode input should be Uint8Array");
          return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
        },
        decode: (digits) => {
          anumArr("radix2.decode", digits);
          return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
        }
      };
    }
    function unsafeWrapper(fn) {
      afn(fn);
      return function(...args) {
        try {
          return fn.apply(null, args);
        } catch (e) {
        }
      };
    }
    function checksum(len, fn) {
      anumber(len);
      afn(fn);
      return {
        encode(data) {
          if (!isBytes(data))
            throw new Error("checksum.encode: input should be Uint8Array");
          const sum = fn(data).slice(0, len);
          const res = new Uint8Array(data.length + len);
          res.set(data);
          res.set(sum, data.length);
          return res;
        },
        decode(data) {
          if (!isBytes(data))
            throw new Error("checksum.decode: input should be Uint8Array");
          const payload = data.slice(0, -len);
          const oldChecksum = data.slice(-len);
          const newChecksum = fn(payload).slice(0, len);
          for (let i = 0; i < len; i++)
            if (newChecksum[i] !== oldChecksum[i])
              throw new Error("Invalid checksum");
          return payload;
        }
      };
    }
    exports$1.utils = {
      alphabet,
      chain,
      checksum,
      convertRadix,
      convertRadix2,
      radix,
      radix2,
      join: join3,
      padding
    };
    exports$1.base16 = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(4), /* @__PURE__ */ alphabet("0123456789ABCDEF"), /* @__PURE__ */ join3(""));
    exports$1.base32 = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ padding(5), /* @__PURE__ */ join3(""));
    exports$1.base32nopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), /* @__PURE__ */ join3(""));
    exports$1.base32hex = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ padding(5), /* @__PURE__ */ join3(""));
    exports$1.base32hexnopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), /* @__PURE__ */ join3(""));
    exports$1.base32crockford = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(5), /* @__PURE__ */ alphabet("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), /* @__PURE__ */ join3(""), /* @__PURE__ */ normalize((s) => s.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1")));
    var hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === "function" && typeof Uint8Array.fromBase64 === "function")();
    var decodeBase64Builtin = (s, isUrl) => {
      astr("base64", s);
      const re = isUrl ? /^[A-Za-z0-9=_-]+$/ : /^[A-Za-z0-9=+/]+$/;
      const alphabet2 = isUrl ? "base64url" : "base64";
      if (s.length > 0 && !re.test(s))
        throw new Error("invalid base64");
      return Uint8Array.fromBase64(s, { alphabet: alphabet2, lastChunkHandling: "strict" });
    };
    exports$1.base64 = hasBase64Builtin ? {
      encode(b) {
        abytes(b);
        return b.toBase64();
      },
      decode(s) {
        return decodeBase64Builtin(s, false);
      }
    } : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ padding(6), /* @__PURE__ */ join3(""));
    exports$1.base64nopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), /* @__PURE__ */ join3(""));
    exports$1.base64url = hasBase64Builtin ? {
      encode(b) {
        abytes(b);
        return b.toBase64({ alphabet: "base64url" });
      },
      decode(s) {
        return decodeBase64Builtin(s, true);
      }
    } : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ padding(6), /* @__PURE__ */ join3(""));
    exports$1.base64urlnopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ join3(""));
    var genBase58 = /* @__NO_SIDE_EFFECTS__ */ (abc) => /* @__PURE__ */ chain(/* @__PURE__ */ radix(58), /* @__PURE__ */ alphabet(abc), /* @__PURE__ */ join3(""));
    exports$1.base58 = /* @__PURE__ */ genBase58("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    exports$1.base58flickr = /* @__PURE__ */ genBase58("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
    exports$1.base58xrp = /* @__PURE__ */ genBase58("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
    var XMR_BLOCK_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    exports$1.base58xmr = {
      encode(data) {
        let res = "";
        for (let i = 0; i < data.length; i += 8) {
          const block = data.subarray(i, i + 8);
          res += exports$1.base58.encode(block).padStart(XMR_BLOCK_LEN[block.length], "1");
        }
        return res;
      },
      decode(str) {
        let res = [];
        for (let i = 0; i < str.length; i += 11) {
          const slice = str.slice(i, i + 11);
          const blockLen = XMR_BLOCK_LEN.indexOf(slice.length);
          const block = exports$1.base58.decode(slice);
          for (let j = 0; j < block.length - blockLen; j++) {
            if (block[j] !== 0)
              throw new Error("base58xmr: wrong padding");
          }
          res = res.concat(Array.from(block.slice(block.length - blockLen)));
        }
        return Uint8Array.from(res);
      }
    };
    var createBase58check = (sha256) => /* @__PURE__ */ chain(checksum(4, (data) => sha256(sha256(data))), exports$1.base58);
    exports$1.createBase58check = createBase58check;
    exports$1.base58check = exports$1.createBase58check;
    var BECH_ALPHABET = /* @__PURE__ */ chain(/* @__PURE__ */ alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), /* @__PURE__ */ join3(""));
    var POLYMOD_GENERATORS = [996825010, 642813549, 513874426, 1027748829, 705979059];
    function bech32Polymod(pre) {
      const b = pre >> 25;
      let chk = (pre & 33554431) << 5;
      for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
        if ((b >> i & 1) === 1)
          chk ^= POLYMOD_GENERATORS[i];
      }
      return chk;
    }
    function bechChecksum(prefix, words, encodingConst = 1) {
      const len = prefix.length;
      let chk = 1;
      for (let i = 0; i < len; i++) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
          throw new Error(`Invalid prefix (${prefix})`);
        chk = bech32Polymod(chk) ^ c >> 5;
      }
      chk = bech32Polymod(chk);
      for (let i = 0; i < len; i++)
        chk = bech32Polymod(chk) ^ prefix.charCodeAt(i) & 31;
      for (let v of words)
        chk = bech32Polymod(chk) ^ v;
      for (let i = 0; i < 6; i++)
        chk = bech32Polymod(chk);
      chk ^= encodingConst;
      return BECH_ALPHABET.encode(convertRadix2([chk % powers[30]], 30, 5, false));
    }
    // @__NO_SIDE_EFFECTS__
    function genBech32(encoding) {
      const ENCODING_CONST = encoding === "bech32" ? 1 : 734539939;
      const _words = /* @__PURE__ */ radix2(5);
      const fromWords = _words.decode;
      const toWords = _words.encode;
      const fromWordsUnsafe = unsafeWrapper(fromWords);
      function encode2(prefix, words, limit = 90) {
        astr("bech32.encode prefix", prefix);
        if (isBytes(words))
          words = Array.from(words);
        anumArr("bech32.encode", words);
        const plen = prefix.length;
        if (plen === 0)
          throw new TypeError(`Invalid prefix length ${plen}`);
        const actualLength = plen + 7 + words.length;
        if (limit !== false && actualLength > limit)
          throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
        const lowered = prefix.toLowerCase();
        const sum = bechChecksum(lowered, words, ENCODING_CONST);
        return `${lowered}1${BECH_ALPHABET.encode(words)}${sum}`;
      }
      function decode7(str, limit = 90) {
        astr("bech32.decode input", str);
        const slen = str.length;
        if (slen < 8 || limit !== false && slen > limit)
          throw new TypeError(`invalid string length: ${slen} (${str}). Expected (8..${limit})`);
        const lowered = str.toLowerCase();
        if (str !== lowered && str !== str.toUpperCase())
          throw new Error(`String must be lowercase or uppercase`);
        const sepIndex = lowered.lastIndexOf("1");
        if (sepIndex === 0 || sepIndex === -1)
          throw new Error(`Letter "1" must be present between prefix and data only`);
        const prefix = lowered.slice(0, sepIndex);
        const data = lowered.slice(sepIndex + 1);
        if (data.length < 6)
          throw new Error("Data must be at least 6 characters long");
        const words = BECH_ALPHABET.decode(data).slice(0, -6);
        const sum = bechChecksum(prefix, words, ENCODING_CONST);
        if (!data.endsWith(sum))
          throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
        return { prefix, words };
      }
      const decodeUnsafe = unsafeWrapper(decode7);
      function decodeToBytes(str) {
        const { prefix, words } = decode7(str, false);
        return { prefix, words, bytes: fromWords(words) };
      }
      function encodeFromBytes(prefix, bytes) {
        return encode2(prefix, toWords(bytes));
      }
      return {
        encode: encode2,
        decode: decode7,
        encodeFromBytes,
        decodeToBytes,
        decodeUnsafe,
        fromWords,
        fromWordsUnsafe,
        toWords
      };
    }
    exports$1.bech32 = /* @__PURE__ */ genBech32("bech32");
    exports$1.bech32m = /* @__PURE__ */ genBech32("bech32m");
    exports$1.utf8 = {
      encode: (data) => new TextDecoder().decode(data),
      decode: (str) => new TextEncoder().encode(str)
    };
    var hasHexBuiltin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
    var hexBuiltin = {
      encode(data) {
        abytes(data);
        return data.toHex();
      },
      decode(s) {
        astr("hex", s);
        return Uint8Array.fromHex(s);
      }
    };
    exports$1.hex = hasHexBuiltin ? hexBuiltin : /* @__PURE__ */ chain(/* @__PURE__ */ radix2(4), /* @__PURE__ */ alphabet("0123456789abcdef"), /* @__PURE__ */ join3(""), /* @__PURE__ */ normalize((s) => {
      if (typeof s !== "string" || s.length % 2 !== 0)
        throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
      return s.toLowerCase();
    }));
    var CODERS = {
      utf8: exports$1.utf8,
      hex: exports$1.hex,
      base16: exports$1.base16,
      base32: exports$1.base32,
      base64: exports$1.base64,
      base64url: exports$1.base64url,
      base58: exports$1.base58,
      base58xmr: exports$1.base58xmr
    };
    var coderTypeError = "Invalid encoding type. Available types: utf8, hex, base16, base32, base64, base64url, base58, base58xmr";
    var bytesToString = (type, bytes) => {
      if (typeof type !== "string" || !CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
      if (!isBytes(bytes))
        throw new TypeError("bytesToString() expects Uint8Array");
      return CODERS[type].encode(bytes);
    };
    exports$1.bytesToString = bytesToString;
    exports$1.str = exports$1.bytesToString;
    var stringToBytes = (type, str) => {
      if (!CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
      if (typeof str !== "string")
        throw new TypeError("stringToBytes() expects string");
      return CODERS[type].decode(str);
    };
    exports$1.stringToBytes = stringToBytes;
    exports$1.bytes = exports$1.stringToBytes;
  }
});

// node_modules/@xrplf/isomorphic/dist/internal/normalizeInput.js
var require_normalizeInput = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/internal/normalizeInput.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    function normalizeInput(input) {
      return Array.isArray(input) ? new Uint8Array(input) : input;
    }
    exports$1.default = normalizeInput;
  }
});

// node_modules/@xrplf/isomorphic/dist/internal/wrapCryptoCreateHash.js
var require_wrapCryptoCreateHash = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/internal/wrapCryptoCreateHash.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var normalizeInput_1 = __importDefault(require_normalizeInput());
    function wrapCryptoCreateHash(type, fn) {
      function hashFn(input) {
        return fn(type).update((0, normalizeInput_1.default)(input)).digest();
      }
      hashFn.create = () => {
        const hash2 = fn(type);
        return {
          update(input) {
            hash2.update((0, normalizeInput_1.default)(input));
            return this;
          },
          digest() {
            return hash2.digest();
          }
        };
      };
      return hashFn;
    }
    exports$1.default = wrapCryptoCreateHash;
  }
});

// node_modules/@xrplf/isomorphic/dist/sha256/index.js
var require_sha256 = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/sha256/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.sha256 = void 0;
    var crypto_1 = __require("crypto");
    var wrapCryptoCreateHash_1 = __importDefault(require_wrapCryptoCreateHash());
    exports$1.sha256 = (0, wrapCryptoCreateHash_1.default)("sha256", crypto_1.createHash);
  }
});

// node_modules/ripple-address-codec/dist/utils.js
var require_utils3 = __commonJS({
  "node_modules/ripple-address-codec/dist/utils.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.concatArgs = exports$1.arrayEqual = void 0;
    function arrayEqual(arr1, arr2) {
      if (arr1.length !== arr2.length) {
        return false;
      }
      return arr1.every((value, index) => value === arr2[index]);
    }
    exports$1.arrayEqual = arrayEqual;
    function isScalar(val) {
      return typeof val === "number";
    }
    function concatArgs(...args) {
      return args.flatMap((arg) => {
        return isScalar(arg) ? [arg] : Array.from(arg);
      });
    }
    exports$1.concatArgs = concatArgs;
  }
});

// node_modules/ripple-address-codec/dist/xrp-codec.js
var require_xrp_codec = __commonJS({
  "node_modules/ripple-address-codec/dist/xrp-codec.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.isValidClassicAddress = exports$1.decodeAccountPublic = exports$1.encodeAccountPublic = exports$1.encodeNodePublic = exports$1.decodeNodePublic = exports$1.decodeAddress = exports$1.decodeAccountID = exports$1.encodeAddress = exports$1.encodeAccountID = exports$1.decodeSeed = exports$1.encodeSeed = exports$1.codec = void 0;
    var base_1 = require_lib();
    var sha256_1 = require_sha256();
    var utils_1 = require_utils3();
    var Codec = class {
      constructor(options) {
        this._sha256 = options.sha256;
        this._codec = base_1.base58xrp;
      }
      /**
       * Encoder.
       *
       * @param bytes - Uint8Array of data to encode.
       * @param opts - Options object including the version bytes and the expected length of the data to encode.
       */
      encode(bytes, opts) {
        const versions = opts.versions;
        return this._encodeVersioned(bytes, versions, opts.expectedLength);
      }
      /**
       * Decoder.
       *
       * @param base58string - Base58Check-encoded string to decode.
       * @param opts - Options object including the version byte(s) and the expected length of the data after decoding.
       */
      /* eslint-disable max-lines-per-function --
       * TODO refactor */
      decode(base58string, opts) {
        var _a;
        const versions = opts.versions;
        const types = opts.versionTypes;
        const withoutSum = this.decodeChecked(base58string);
        if (versions.length > 1 && !opts.expectedLength) {
          throw new Error("expectedLength is required because there are >= 2 possible versions");
        }
        const versionLengthGuess = typeof versions[0] === "number" ? 1 : versions[0].length;
        const payloadLength = (_a = opts.expectedLength) !== null && _a !== void 0 ? _a : withoutSum.length - versionLengthGuess;
        const versionBytes = withoutSum.slice(0, -payloadLength);
        const payload = withoutSum.slice(-payloadLength);
        for (let i = 0; i < versions.length; i++) {
          const version = Array.isArray(versions[i]) ? versions[i] : [versions[i]];
          if ((0, utils_1.arrayEqual)(versionBytes, version)) {
            return {
              version,
              bytes: payload,
              type: types ? types[i] : null
            };
          }
        }
        throw new Error("version_invalid: version bytes do not match any of the provided version(s)");
      }
      encodeChecked(bytes) {
        const check = this._sha256(this._sha256(bytes)).slice(0, 4);
        return this._encodeRaw(Uint8Array.from((0, utils_1.concatArgs)(bytes, check)));
      }
      decodeChecked(base58string) {
        const intArray = this._decodeRaw(base58string);
        if (intArray.byteLength < 5) {
          throw new Error("invalid_input_size: decoded data must have length >= 5");
        }
        if (!this._verifyCheckSum(intArray)) {
          throw new Error("checksum_invalid");
        }
        return intArray.slice(0, -4);
      }
      _encodeVersioned(bytes, versions, expectedLength) {
        if (!checkByteLength(bytes, expectedLength)) {
          throw new Error("unexpected_payload_length: bytes.length does not match expectedLength. Ensure that the bytes are a Uint8Array.");
        }
        return this.encodeChecked((0, utils_1.concatArgs)(versions, bytes));
      }
      _encodeRaw(bytes) {
        return this._codec.encode(Uint8Array.from(bytes));
      }
      /* eslint-enable max-lines-per-function */
      _decodeRaw(base58string) {
        return this._codec.decode(base58string);
      }
      _verifyCheckSum(bytes) {
        const computed = this._sha256(this._sha256(bytes.slice(0, -4))).slice(0, 4);
        const checksum = bytes.slice(-4);
        return (0, utils_1.arrayEqual)(computed, checksum);
      }
    };
    var ACCOUNT_ID = 0;
    var ACCOUNT_PUBLIC_KEY = 35;
    var FAMILY_SEED = 33;
    var NODE_PUBLIC = 28;
    var ED25519_SEED = [1, 225, 75];
    var codecOptions = {
      sha256: sha256_1.sha256
    };
    var codecWithXrpAlphabet = new Codec(codecOptions);
    exports$1.codec = codecWithXrpAlphabet;
    function encodeSeed(entropy, type) {
      if (!checkByteLength(entropy, 16)) {
        throw new Error("entropy must have length 16");
      }
      const opts = {
        expectedLength: 16,
        // for secp256k1, use `FAMILY_SEED`
        versions: type === "ed25519" ? ED25519_SEED : [FAMILY_SEED]
      };
      return codecWithXrpAlphabet.encode(entropy, opts);
    }
    exports$1.encodeSeed = encodeSeed;
    function decodeSeed(seed, opts = {
      versionTypes: ["ed25519", "secp256k1"],
      versions: [ED25519_SEED, FAMILY_SEED],
      expectedLength: 16
    }) {
      return codecWithXrpAlphabet.decode(seed, opts);
    }
    exports$1.decodeSeed = decodeSeed;
    function encodeAccountID(bytes) {
      const opts = { versions: [ACCOUNT_ID], expectedLength: 20 };
      return codecWithXrpAlphabet.encode(bytes, opts);
    }
    exports$1.encodeAccountID = encodeAccountID;
    exports$1.encodeAddress = encodeAccountID;
    function decodeAccountID(accountId) {
      const opts = { versions: [ACCOUNT_ID], expectedLength: 20 };
      return codecWithXrpAlphabet.decode(accountId, opts).bytes;
    }
    exports$1.decodeAccountID = decodeAccountID;
    exports$1.decodeAddress = decodeAccountID;
    function decodeNodePublic(base58string) {
      const opts = { versions: [NODE_PUBLIC], expectedLength: 33 };
      return codecWithXrpAlphabet.decode(base58string, opts).bytes;
    }
    exports$1.decodeNodePublic = decodeNodePublic;
    function encodeNodePublic(bytes) {
      const opts = { versions: [NODE_PUBLIC], expectedLength: 33 };
      return codecWithXrpAlphabet.encode(bytes, opts);
    }
    exports$1.encodeNodePublic = encodeNodePublic;
    function encodeAccountPublic(bytes) {
      const opts = { versions: [ACCOUNT_PUBLIC_KEY], expectedLength: 33 };
      return codecWithXrpAlphabet.encode(bytes, opts);
    }
    exports$1.encodeAccountPublic = encodeAccountPublic;
    function decodeAccountPublic(base58string) {
      const opts = { versions: [ACCOUNT_PUBLIC_KEY], expectedLength: 33 };
      return codecWithXrpAlphabet.decode(base58string, opts).bytes;
    }
    exports$1.decodeAccountPublic = decodeAccountPublic;
    function isValidClassicAddress(address) {
      try {
        decodeAccountID(address);
      } catch (_error) {
        return false;
      }
      return true;
    }
    exports$1.isValidClassicAddress = isValidClassicAddress;
    function checkByteLength(bytes, expectedLength) {
      return "byteLength" in bytes ? bytes.byteLength === expectedLength : bytes.length === expectedLength;
    }
  }
});

// node_modules/ripple-address-codec/dist/index.js
var require_dist = __commonJS({
  "node_modules/ripple-address-codec/dist/index.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.isValidXAddress = exports$1.decodeXAddress = exports$1.xAddressToClassicAddress = exports$1.encodeXAddress = exports$1.classicAddressToXAddress = exports$1.isValidClassicAddress = exports$1.decodeAccountPublic = exports$1.encodeAccountPublic = exports$1.decodeNodePublic = exports$1.encodeNodePublic = exports$1.decodeAccountID = exports$1.encodeAccountID = exports$1.decodeSeed = exports$1.encodeSeed = exports$1.codec = void 0;
    var utils_1 = require_utils2();
    var xrp_codec_1 = require_xrp_codec();
    Object.defineProperty(exports$1, "codec", { enumerable: true, get: function() {
      return xrp_codec_1.codec;
    } });
    Object.defineProperty(exports$1, "encodeSeed", { enumerable: true, get: function() {
      return xrp_codec_1.encodeSeed;
    } });
    Object.defineProperty(exports$1, "decodeSeed", { enumerable: true, get: function() {
      return xrp_codec_1.decodeSeed;
    } });
    Object.defineProperty(exports$1, "encodeAccountID", { enumerable: true, get: function() {
      return xrp_codec_1.encodeAccountID;
    } });
    Object.defineProperty(exports$1, "decodeAccountID", { enumerable: true, get: function() {
      return xrp_codec_1.decodeAccountID;
    } });
    Object.defineProperty(exports$1, "encodeNodePublic", { enumerable: true, get: function() {
      return xrp_codec_1.encodeNodePublic;
    } });
    Object.defineProperty(exports$1, "decodeNodePublic", { enumerable: true, get: function() {
      return xrp_codec_1.decodeNodePublic;
    } });
    Object.defineProperty(exports$1, "encodeAccountPublic", { enumerable: true, get: function() {
      return xrp_codec_1.encodeAccountPublic;
    } });
    Object.defineProperty(exports$1, "decodeAccountPublic", { enumerable: true, get: function() {
      return xrp_codec_1.decodeAccountPublic;
    } });
    Object.defineProperty(exports$1, "isValidClassicAddress", { enumerable: true, get: function() {
      return xrp_codec_1.isValidClassicAddress;
    } });
    var PREFIX_BYTES = {
      // 5, 68
      main: Uint8Array.from([5, 68]),
      // 4, 147
      test: Uint8Array.from([4, 147])
    };
    var MAX_32_BIT_UNSIGNED_INT = 4294967295;
    function classicAddressToXAddress(classicAddress, tag, test) {
      const accountId = (0, xrp_codec_1.decodeAccountID)(classicAddress);
      return encodeXAddress(accountId, tag, test);
    }
    exports$1.classicAddressToXAddress = classicAddressToXAddress;
    function encodeXAddress(accountId, tag, test) {
      if (accountId.length !== 20) {
        throw new Error("Account ID must be 20 bytes");
      }
      if (tag !== false && tag > MAX_32_BIT_UNSIGNED_INT) {
        throw new Error("Invalid tag");
      }
      const theTag = tag || 0;
      const flag = tag === false || tag == null ? 0 : 1;
      const bytes = (0, utils_1.concat)([
        test ? PREFIX_BYTES.test : PREFIX_BYTES.main,
        accountId,
        Uint8Array.from([
          // 0x00 if no tag, 0x01 if 32-bit tag
          flag,
          // first byte
          theTag & 255,
          // second byte
          theTag >> 8 & 255,
          // third byte
          theTag >> 16 & 255,
          // fourth byte
          theTag >> 24 & 255,
          0,
          0,
          0,
          // four zero bytes (reserved for 64-bit tags)
          0
        ])
      ]);
      return xrp_codec_1.codec.encodeChecked(bytes);
    }
    exports$1.encodeXAddress = encodeXAddress;
    function xAddressToClassicAddress(xAddress) {
      const { accountId, tag, test } = decodeXAddress(xAddress);
      const classicAddress = (0, xrp_codec_1.encodeAccountID)(accountId);
      return {
        classicAddress,
        tag,
        test
      };
    }
    exports$1.xAddressToClassicAddress = xAddressToClassicAddress;
    function decodeXAddress(xAddress) {
      const decoded = xrp_codec_1.codec.decodeChecked(xAddress);
      const test = isUint8ArrayForTestAddress(decoded);
      const accountId = decoded.slice(2, 22);
      const tag = tagFromUint8Array(decoded);
      return {
        accountId,
        tag,
        test
      };
    }
    exports$1.decodeXAddress = decodeXAddress;
    function isUint8ArrayForTestAddress(buf) {
      const decodedPrefix = buf.slice(0, 2);
      if ((0, utils_1.equal)(PREFIX_BYTES.main, decodedPrefix)) {
        return false;
      }
      if ((0, utils_1.equal)(PREFIX_BYTES.test, decodedPrefix)) {
        return true;
      }
      throw new Error("Invalid X-address: bad prefix");
    }
    function tagFromUint8Array(buf) {
      const flag = buf[22];
      if (flag >= 2) {
        throw new Error("Unsupported X-address");
      }
      if (flag === 1) {
        return buf[23] + buf[24] * 256 + buf[25] * 65536 + buf[26] * 16777216;
      }
      if (flag !== 0) {
        throw new Error("flag must be zero to indicate no tag");
      }
      if (!(0, utils_1.equal)((0, utils_1.hexToBytes)("0000000000000000"), buf.slice(23, 23 + 8))) {
        throw new Error("remaining bytes must be zero");
      }
      return false;
    }
    function isValidXAddress(xAddress) {
      try {
        decodeXAddress(xAddress);
      } catch (_error) {
        return false;
      }
      return true;
    }
    exports$1.isValidXAddress = isValidXAddress;
  }
});

// node_modules/@xrplf/isomorphic/dist/ripemd160/index.js
var require_ripemd160 = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/ripemd160/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.ripemd160 = void 0;
    var crypto_1 = __require("crypto");
    var wrapCryptoCreateHash_1 = __importDefault(require_wrapCryptoCreateHash());
    exports$1.ripemd160 = (0, wrapCryptoCreateHash_1.default)("ripemd160", crypto_1.createHash);
  }
});

// node_modules/@noble/hashes/_md.js
var require_md = __commonJS({
  "node_modules/@noble/hashes/_md.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.SHA512_IV = exports$1.SHA384_IV = exports$1.SHA224_IV = exports$1.SHA256_IV = exports$1.HashMD = void 0;
    exports$1.setBigUint64 = setBigUint64;
    exports$1.Chi = Chi;
    exports$1.Maj = Maj;
    var utils_ts_1 = require_utils();
    function setBigUint64(view, byteOffset, value, isLE) {
      if (typeof view.setBigUint64 === "function")
        return view.setBigUint64(byteOffset, value, isLE);
      const _32n = BigInt(32);
      const _u32_max = BigInt(4294967295);
      const wh = Number(value >> _32n & _u32_max);
      const wl = Number(value & _u32_max);
      const h = isLE ? 4 : 0;
      const l = isLE ? 0 : 4;
      view.setUint32(byteOffset + h, wh, isLE);
      view.setUint32(byteOffset + l, wl, isLE);
    }
    function Chi(a, b, c) {
      return a & b ^ ~a & c;
    }
    function Maj(a, b, c) {
      return a & b ^ a & c ^ b & c;
    }
    var HashMD = class extends utils_ts_1.Hash {
      constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_ts_1.createView)(this.buffer);
      }
      update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len; ) {
          const take = Math.min(blockLen - this.pos, len - pos);
          if (take === blockLen) {
            const dataView = (0, utils_ts_1.createView)(data);
            for (; blockLen <= len - pos; pos += blockLen)
              this.process(dataView, pos);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          pos += take;
          if (this.pos === blockLen) {
            this.process(view, 0);
            this.pos = 0;
          }
        }
        this.length += data.length;
        this.roundClean();
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        this.finished = true;
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        buffer[pos++] = 128;
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        if (this.padOffset > blockLen - pos) {
          this.process(view, 0);
          pos = 0;
        }
        for (let i = pos; i < blockLen; i++)
          buffer[i] = 0;
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_ts_1.createView)(out);
        const len = this.outputLen;
        if (len % 4)
          throw new Error("_sha2: outputLen should be aligned to 32bit");
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
          throw new Error("_sha2: outputLen bigger than state");
        for (let i = 0; i < outLen; i++)
          oview.setUint32(4 * i, state[i], isLE);
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
          to.buffer.set(buffer);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
    exports$1.HashMD = HashMD;
    exports$1.SHA256_IV = Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    exports$1.SHA224_IV = Uint32Array.from([
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ]);
    exports$1.SHA384_IV = Uint32Array.from([
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ]);
    exports$1.SHA512_IV = Uint32Array.from([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
  }
});

// node_modules/@noble/hashes/_u64.js
var require_u64 = __commonJS({
  "node_modules/@noble/hashes/_u64.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.toBig = exports$1.shrSL = exports$1.shrSH = exports$1.rotrSL = exports$1.rotrSH = exports$1.rotrBL = exports$1.rotrBH = exports$1.rotr32L = exports$1.rotr32H = exports$1.rotlSL = exports$1.rotlSH = exports$1.rotlBL = exports$1.rotlBH = exports$1.add5L = exports$1.add5H = exports$1.add4L = exports$1.add4H = exports$1.add3L = exports$1.add3H = void 0;
    exports$1.add = add;
    exports$1.fromBig = fromBig;
    exports$1.split = split;
    var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    var _32n = /* @__PURE__ */ BigInt(32);
    function fromBig(n, le = false) {
      if (le)
        return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
      return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
    }
    function split(lst, le = false) {
      const len = lst.length;
      let Ah = new Uint32Array(len);
      let Al = new Uint32Array(len);
      for (let i = 0; i < len; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
      }
      return [Ah, Al];
    }
    var toBig = (h, l) => BigInt(h >>> 0) << _32n | BigInt(l >>> 0);
    exports$1.toBig = toBig;
    var shrSH = (h, _l, s) => h >>> s;
    exports$1.shrSH = shrSH;
    var shrSL = (h, l, s) => h << 32 - s | l >>> s;
    exports$1.shrSL = shrSL;
    var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
    exports$1.rotrSH = rotrSH;
    var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
    exports$1.rotrSL = rotrSL;
    var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
    exports$1.rotrBH = rotrBH;
    var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
    exports$1.rotrBL = rotrBL;
    var rotr32H = (_h, l) => l;
    exports$1.rotr32H = rotr32H;
    var rotr32L = (h, _l) => h;
    exports$1.rotr32L = rotr32L;
    var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
    exports$1.rotlSH = rotlSH;
    var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
    exports$1.rotlSL = rotlSL;
    var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
    exports$1.rotlBH = rotlBH;
    var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
    exports$1.rotlBL = rotlBL;
    function add(Ah, Al, Bh, Bl) {
      const l = (Al >>> 0) + (Bl >>> 0);
      return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
    }
    var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    exports$1.add3L = add3L;
    var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
    exports$1.add3H = add3H;
    var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    exports$1.add4L = add4L;
    var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
    exports$1.add4H = add4H;
    var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    exports$1.add5L = add5L;
    var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    exports$1.add5H = add5H;
    var u64 = {
      fromBig,
      split,
      toBig,
      shrSH,
      shrSL,
      rotrSH,
      rotrSL,
      rotrBH,
      rotrBL,
      rotr32H,
      rotr32L,
      rotlSH,
      rotlSL,
      rotlBH,
      rotlBL,
      add,
      add3L,
      add3H,
      add4L,
      add4H,
      add5H,
      add5L
    };
    exports$1.default = u64;
  }
});

// node_modules/@noble/hashes/sha2.js
var require_sha2 = __commonJS({
  "node_modules/@noble/hashes/sha2.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.sha512_224 = exports$1.sha512_256 = exports$1.sha384 = exports$1.sha512 = exports$1.sha224 = exports$1.sha256 = exports$1.SHA512_256 = exports$1.SHA512_224 = exports$1.SHA384 = exports$1.SHA512 = exports$1.SHA224 = exports$1.SHA256 = void 0;
    var _md_ts_1 = require_md();
    var u64 = require_u64();
    var utils_ts_1 = require_utils();
    var SHA256_K = /* @__PURE__ */ Uint32Array.from([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
    var SHA256 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        this.A = _md_ts_1.SHA256_IV[0] | 0;
        this.B = _md_ts_1.SHA256_IV[1] | 0;
        this.C = _md_ts_1.SHA256_IV[2] | 0;
        this.D = _md_ts_1.SHA256_IV[3] | 0;
        this.E = _md_ts_1.SHA256_IV[4] | 0;
        this.F = _md_ts_1.SHA256_IV[5] | 0;
        this.G = _md_ts_1.SHA256_IV[6] | 0;
        this.H = _md_ts_1.SHA256_IV[7] | 0;
      }
      get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
      }
      // prettier-ignore
      set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
          SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
          const W15 = SHA256_W[i - 15];
          const W2 = SHA256_W[i - 2];
          const s0 = (0, utils_ts_1.rotr)(W15, 7) ^ (0, utils_ts_1.rotr)(W15, 18) ^ W15 >>> 3;
          const s1 = (0, utils_ts_1.rotr)(W2, 17) ^ (0, utils_ts_1.rotr)(W2, 19) ^ W2 >>> 10;
          SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
        }
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
          const sigma1 = (0, utils_ts_1.rotr)(E, 6) ^ (0, utils_ts_1.rotr)(E, 11) ^ (0, utils_ts_1.rotr)(E, 25);
          const T1 = H + sigma1 + (0, _md_ts_1.Chi)(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
          const sigma0 = (0, utils_ts_1.rotr)(A, 2) ^ (0, utils_ts_1.rotr)(A, 13) ^ (0, utils_ts_1.rotr)(A, 22);
          const T2 = sigma0 + (0, _md_ts_1.Maj)(A, B, C) | 0;
          H = G;
          G = F;
          F = E;
          E = D + T1 | 0;
          D = C;
          C = B;
          B = A;
          A = T1 + T2 | 0;
        }
        A = A + this.A | 0;
        B = B + this.B | 0;
        C = C + this.C | 0;
        D = D + this.D | 0;
        E = E + this.E | 0;
        F = F + this.F | 0;
        G = G + this.G | 0;
        H = H + this.H | 0;
        this.set(A, B, C, D, E, F, G, H);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA256_W);
      }
      destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        (0, utils_ts_1.clean)(this.buffer);
      }
    };
    exports$1.SHA256 = SHA256;
    var SHA224 = class extends SHA256 {
      constructor() {
        super(28);
        this.A = _md_ts_1.SHA224_IV[0] | 0;
        this.B = _md_ts_1.SHA224_IV[1] | 0;
        this.C = _md_ts_1.SHA224_IV[2] | 0;
        this.D = _md_ts_1.SHA224_IV[3] | 0;
        this.E = _md_ts_1.SHA224_IV[4] | 0;
        this.F = _md_ts_1.SHA224_IV[5] | 0;
        this.G = _md_ts_1.SHA224_IV[6] | 0;
        this.H = _md_ts_1.SHA224_IV[7] | 0;
      }
    };
    exports$1.SHA224 = SHA224;
    var K512 = /* @__PURE__ */ (() => u64.split([
      "0x428a2f98d728ae22",
      "0x7137449123ef65cd",
      "0xb5c0fbcfec4d3b2f",
      "0xe9b5dba58189dbbc",
      "0x3956c25bf348b538",
      "0x59f111f1b605d019",
      "0x923f82a4af194f9b",
      "0xab1c5ed5da6d8118",
      "0xd807aa98a3030242",
      "0x12835b0145706fbe",
      "0x243185be4ee4b28c",
      "0x550c7dc3d5ffb4e2",
      "0x72be5d74f27b896f",
      "0x80deb1fe3b1696b1",
      "0x9bdc06a725c71235",
      "0xc19bf174cf692694",
      "0xe49b69c19ef14ad2",
      "0xefbe4786384f25e3",
      "0x0fc19dc68b8cd5b5",
      "0x240ca1cc77ac9c65",
      "0x2de92c6f592b0275",
      "0x4a7484aa6ea6e483",
      "0x5cb0a9dcbd41fbd4",
      "0x76f988da831153b5",
      "0x983e5152ee66dfab",
      "0xa831c66d2db43210",
      "0xb00327c898fb213f",
      "0xbf597fc7beef0ee4",
      "0xc6e00bf33da88fc2",
      "0xd5a79147930aa725",
      "0x06ca6351e003826f",
      "0x142929670a0e6e70",
      "0x27b70a8546d22ffc",
      "0x2e1b21385c26c926",
      "0x4d2c6dfc5ac42aed",
      "0x53380d139d95b3df",
      "0x650a73548baf63de",
      "0x766a0abb3c77b2a8",
      "0x81c2c92e47edaee6",
      "0x92722c851482353b",
      "0xa2bfe8a14cf10364",
      "0xa81a664bbc423001",
      "0xc24b8b70d0f89791",
      "0xc76c51a30654be30",
      "0xd192e819d6ef5218",
      "0xd69906245565a910",
      "0xf40e35855771202a",
      "0x106aa07032bbd1b8",
      "0x19a4c116b8d2d0c8",
      "0x1e376c085141ab53",
      "0x2748774cdf8eeb99",
      "0x34b0bcb5e19b48a8",
      "0x391c0cb3c5c95a63",
      "0x4ed8aa4ae3418acb",
      "0x5b9cca4f7763e373",
      "0x682e6ff3d6b2b8a3",
      "0x748f82ee5defb2fc",
      "0x78a5636f43172f60",
      "0x84c87814a1f0ab72",
      "0x8cc702081a6439ec",
      "0x90befffa23631e28",
      "0xa4506cebde82bde9",
      "0xbef9a3f7b2c67915",
      "0xc67178f2e372532b",
      "0xca273eceea26619c",
      "0xd186b8c721c0c207",
      "0xeada7dd6cde0eb1e",
      "0xf57d4f7fee6ed178",
      "0x06f067aa72176fba",
      "0x0a637dc5a2c898a6",
      "0x113f9804bef90dae",
      "0x1b710b35131c471b",
      "0x28db77f523047d84",
      "0x32caab7b40c72493",
      "0x3c9ebe0a15c9bebc",
      "0x431d67c49c100d4c",
      "0x4cc5d4becb3e42b6",
      "0x597f299cfc657e2a",
      "0x5fcb6fab3ad6faec",
      "0x6c44198c4a475817"
    ].map((n) => BigInt(n))))();
    var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
    var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
    var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
    var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
    var SHA512 = class extends _md_ts_1.HashMD {
      constructor(outputLen = 64) {
        super(128, outputLen, 16, false);
        this.Ah = _md_ts_1.SHA512_IV[0] | 0;
        this.Al = _md_ts_1.SHA512_IV[1] | 0;
        this.Bh = _md_ts_1.SHA512_IV[2] | 0;
        this.Bl = _md_ts_1.SHA512_IV[3] | 0;
        this.Ch = _md_ts_1.SHA512_IV[4] | 0;
        this.Cl = _md_ts_1.SHA512_IV[5] | 0;
        this.Dh = _md_ts_1.SHA512_IV[6] | 0;
        this.Dl = _md_ts_1.SHA512_IV[7] | 0;
        this.Eh = _md_ts_1.SHA512_IV[8] | 0;
        this.El = _md_ts_1.SHA512_IV[9] | 0;
        this.Fh = _md_ts_1.SHA512_IV[10] | 0;
        this.Fl = _md_ts_1.SHA512_IV[11] | 0;
        this.Gh = _md_ts_1.SHA512_IV[12] | 0;
        this.Gl = _md_ts_1.SHA512_IV[13] | 0;
        this.Hh = _md_ts_1.SHA512_IV[14] | 0;
        this.Hl = _md_ts_1.SHA512_IV[15] | 0;
      }
      // prettier-ignore
      get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
      }
      // prettier-ignore
      set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
      }
      process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4) {
          SHA512_W_H[i] = view.getUint32(offset);
          SHA512_W_L[i] = view.getUint32(offset += 4);
        }
        for (let i = 16; i < 80; i++) {
          const W15h = SHA512_W_H[i - 15] | 0;
          const W15l = SHA512_W_L[i - 15] | 0;
          const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
          const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
          const W2h = SHA512_W_H[i - 2] | 0;
          const W2l = SHA512_W_L[i - 2] | 0;
          const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
          const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
          const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
          const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
          SHA512_W_H[i] = SUMh | 0;
          SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        for (let i = 0; i < 80; i++) {
          const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
          const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
          const CHIh = Eh & Fh ^ ~Eh & Gh;
          const CHIl = El & Fl ^ ~El & Gl;
          const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
          const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
          const T1l = T1ll | 0;
          const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
          const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
          const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
          const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
          Hh = Gh | 0;
          Hl = Gl | 0;
          Gh = Fh | 0;
          Gl = Fl | 0;
          Fh = Eh | 0;
          Fl = El | 0;
          ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
          Dh = Ch | 0;
          Dl = Cl | 0;
          Ch = Bh | 0;
          Cl = Bl | 0;
          Bh = Ah | 0;
          Bl = Al | 0;
          const All = u64.add3L(T1l, sigma0l, MAJl);
          Ah = u64.add3H(All, T1h, sigma0h, MAJh);
          Al = All | 0;
        }
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
      }
      roundClean() {
        (0, utils_ts_1.clean)(SHA512_W_H, SHA512_W_L);
      }
      destroy() {
        (0, utils_ts_1.clean)(this.buffer);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      }
    };
    exports$1.SHA512 = SHA512;
    var SHA384 = class extends SHA512 {
      constructor() {
        super(48);
        this.Ah = _md_ts_1.SHA384_IV[0] | 0;
        this.Al = _md_ts_1.SHA384_IV[1] | 0;
        this.Bh = _md_ts_1.SHA384_IV[2] | 0;
        this.Bl = _md_ts_1.SHA384_IV[3] | 0;
        this.Ch = _md_ts_1.SHA384_IV[4] | 0;
        this.Cl = _md_ts_1.SHA384_IV[5] | 0;
        this.Dh = _md_ts_1.SHA384_IV[6] | 0;
        this.Dl = _md_ts_1.SHA384_IV[7] | 0;
        this.Eh = _md_ts_1.SHA384_IV[8] | 0;
        this.El = _md_ts_1.SHA384_IV[9] | 0;
        this.Fh = _md_ts_1.SHA384_IV[10] | 0;
        this.Fl = _md_ts_1.SHA384_IV[11] | 0;
        this.Gh = _md_ts_1.SHA384_IV[12] | 0;
        this.Gl = _md_ts_1.SHA384_IV[13] | 0;
        this.Hh = _md_ts_1.SHA384_IV[14] | 0;
        this.Hl = _md_ts_1.SHA384_IV[15] | 0;
      }
    };
    exports$1.SHA384 = SHA384;
    var T224_IV = /* @__PURE__ */ Uint32Array.from([
      2352822216,
      424955298,
      1944164710,
      2312950998,
      502970286,
      855612546,
      1738396948,
      1479516111,
      258812777,
      2077511080,
      2011393907,
      79989058,
      1067287976,
      1780299464,
      286451373,
      2446758561
    ]);
    var T256_IV = /* @__PURE__ */ Uint32Array.from([
      573645204,
      4230739756,
      2673172387,
      3360449730,
      596883563,
      1867755857,
      2520282905,
      1497426621,
      2519219938,
      2827943907,
      3193839141,
      1401305490,
      721525244,
      746961066,
      246885852,
      2177182882
    ]);
    var SHA512_224 = class extends SHA512 {
      constructor() {
        super(28);
        this.Ah = T224_IV[0] | 0;
        this.Al = T224_IV[1] | 0;
        this.Bh = T224_IV[2] | 0;
        this.Bl = T224_IV[3] | 0;
        this.Ch = T224_IV[4] | 0;
        this.Cl = T224_IV[5] | 0;
        this.Dh = T224_IV[6] | 0;
        this.Dl = T224_IV[7] | 0;
        this.Eh = T224_IV[8] | 0;
        this.El = T224_IV[9] | 0;
        this.Fh = T224_IV[10] | 0;
        this.Fl = T224_IV[11] | 0;
        this.Gh = T224_IV[12] | 0;
        this.Gl = T224_IV[13] | 0;
        this.Hh = T224_IV[14] | 0;
        this.Hl = T224_IV[15] | 0;
      }
    };
    exports$1.SHA512_224 = SHA512_224;
    var SHA512_256 = class extends SHA512 {
      constructor() {
        super(32);
        this.Ah = T256_IV[0] | 0;
        this.Al = T256_IV[1] | 0;
        this.Bh = T256_IV[2] | 0;
        this.Bl = T256_IV[3] | 0;
        this.Ch = T256_IV[4] | 0;
        this.Cl = T256_IV[5] | 0;
        this.Dh = T256_IV[6] | 0;
        this.Dl = T256_IV[7] | 0;
        this.Eh = T256_IV[8] | 0;
        this.El = T256_IV[9] | 0;
        this.Fh = T256_IV[10] | 0;
        this.Fl = T256_IV[11] | 0;
        this.Gh = T256_IV[12] | 0;
        this.Gl = T256_IV[13] | 0;
        this.Hh = T256_IV[14] | 0;
        this.Hl = T256_IV[15] | 0;
      }
    };
    exports$1.SHA512_256 = SHA512_256;
    exports$1.sha256 = (0, utils_ts_1.createHasher)(() => new SHA256());
    exports$1.sha224 = (0, utils_ts_1.createHasher)(() => new SHA224());
    exports$1.sha512 = (0, utils_ts_1.createHasher)(() => new SHA512());
    exports$1.sha384 = (0, utils_ts_1.createHasher)(() => new SHA384());
    exports$1.sha512_256 = (0, utils_ts_1.createHasher)(() => new SHA512_256());
    exports$1.sha512_224 = (0, utils_ts_1.createHasher)(() => new SHA512_224());
  }
});

// node_modules/@noble/hashes/hmac.js
var require_hmac = __commonJS({
  "node_modules/@noble/hashes/hmac.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.hmac = exports$1.HMAC = void 0;
    var utils_ts_1 = require_utils();
    var HMAC = class extends utils_ts_1.Hash {
      constructor(hash2, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        (0, utils_ts_1.ahash)(hash2);
        const key = (0, utils_ts_1.toBytes)(_key);
        this.iHash = hash2.create();
        if (typeof this.iHash.update !== "function")
          throw new Error("Expected instance of class which extends utils.Hash");
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54;
        this.iHash.update(pad);
        this.oHash = hash2.create();
        for (let i = 0; i < pad.length; i++)
          pad[i] ^= 54 ^ 92;
        this.oHash.update(pad);
        (0, utils_ts_1.clean)(pad);
      }
      update(buf) {
        (0, utils_ts_1.aexists)(this);
        this.iHash.update(buf);
        return this;
      }
      digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.abytes)(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
      }
      digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
      }
      _cloneInto(to) {
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
      }
      clone() {
        return this._cloneInto();
      }
      destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
      }
    };
    exports$1.HMAC = HMAC;
    var hmac = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
    exports$1.hmac = hmac;
    exports$1.hmac.create = (hash2, key) => new HMAC(hash2, key);
  }
});

// node_modules/@noble/curves/utils.js
var require_utils4 = __commonJS({
  "node_modules/@noble/curves/utils.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.notImplemented = exports$1.bitMask = exports$1.utf8ToBytes = exports$1.randomBytes = exports$1.isBytes = exports$1.hexToBytes = exports$1.concatBytes = exports$1.bytesToUtf8 = exports$1.bytesToHex = exports$1.anumber = exports$1.abytes = void 0;
    exports$1.abool = abool;
    exports$1._abool2 = _abool2;
    exports$1._abytes2 = _abytes2;
    exports$1.numberToHexUnpadded = numberToHexUnpadded;
    exports$1.hexToNumber = hexToNumber;
    exports$1.bytesToNumberBE = bytesToNumberBE;
    exports$1.bytesToNumberLE = bytesToNumberLE;
    exports$1.numberToBytesBE = numberToBytesBE;
    exports$1.numberToBytesLE = numberToBytesLE;
    exports$1.numberToVarBytesBE = numberToVarBytesBE;
    exports$1.ensureBytes = ensureBytes;
    exports$1.equalBytes = equalBytes;
    exports$1.copyBytes = copyBytes;
    exports$1.asciiToBytes = asciiToBytes;
    exports$1.inRange = inRange;
    exports$1.aInRange = aInRange;
    exports$1.bitLen = bitLen;
    exports$1.bitGet = bitGet;
    exports$1.bitSet = bitSet;
    exports$1.createHmacDrbg = createHmacDrbg;
    exports$1.validateObject = validateObject;
    exports$1.isHash = isHash;
    exports$1._validateObject = _validateObject;
    exports$1.memoized = memoized;
    var utils_js_1 = require_utils();
    var utils_js_2 = require_utils();
    Object.defineProperty(exports$1, "abytes", { enumerable: true, get: function() {
      return utils_js_2.abytes;
    } });
    Object.defineProperty(exports$1, "anumber", { enumerable: true, get: function() {
      return utils_js_2.anumber;
    } });
    Object.defineProperty(exports$1, "bytesToHex", { enumerable: true, get: function() {
      return utils_js_2.bytesToHex;
    } });
    Object.defineProperty(exports$1, "bytesToUtf8", { enumerable: true, get: function() {
      return utils_js_2.bytesToUtf8;
    } });
    Object.defineProperty(exports$1, "concatBytes", { enumerable: true, get: function() {
      return utils_js_2.concatBytes;
    } });
    Object.defineProperty(exports$1, "hexToBytes", { enumerable: true, get: function() {
      return utils_js_2.hexToBytes;
    } });
    Object.defineProperty(exports$1, "isBytes", { enumerable: true, get: function() {
      return utils_js_2.isBytes;
    } });
    Object.defineProperty(exports$1, "randomBytes", { enumerable: true, get: function() {
      return utils_js_2.randomBytes;
    } });
    Object.defineProperty(exports$1, "utf8ToBytes", { enumerable: true, get: function() {
      return utils_js_2.utf8ToBytes;
    } });
    var _0n = /* @__PURE__ */ BigInt(0);
    var _1n = /* @__PURE__ */ BigInt(1);
    function abool(title, value) {
      if (typeof value !== "boolean")
        throw new Error(title + " boolean expected, got " + value);
    }
    function _abool2(value, title = "") {
      if (typeof value !== "boolean") {
        const prefix = title && `"${title}"`;
        throw new Error(prefix + "expected boolean, got type=" + typeof value);
      }
      return value;
    }
    function _abytes2(value, length, title = "") {
      const bytes = (0, utils_js_1.isBytes)(value);
      const len = value?.length;
      const needsLen = length !== void 0;
      if (!bytes || needsLen && len !== length) {
        const prefix = title && `"${title}" `;
        const ofLen = needsLen ? ` of length ${length}` : "";
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
      }
      return value;
    }
    function numberToHexUnpadded(num) {
      const hex = num.toString(16);
      return hex.length & 1 ? "0" + hex : hex;
    }
    function hexToNumber(hex) {
      if (typeof hex !== "string")
        throw new Error("hex string expected, got " + typeof hex);
      return hex === "" ? _0n : BigInt("0x" + hex);
    }
    function bytesToNumberBE(bytes) {
      return hexToNumber((0, utils_js_1.bytesToHex)(bytes));
    }
    function bytesToNumberLE(bytes) {
      (0, utils_js_1.abytes)(bytes);
      return hexToNumber((0, utils_js_1.bytesToHex)(Uint8Array.from(bytes).reverse()));
    }
    function numberToBytesBE(n, len) {
      return (0, utils_js_1.hexToBytes)(n.toString(16).padStart(len * 2, "0"));
    }
    function numberToBytesLE(n, len) {
      return numberToBytesBE(n, len).reverse();
    }
    function numberToVarBytesBE(n) {
      return (0, utils_js_1.hexToBytes)(numberToHexUnpadded(n));
    }
    function ensureBytes(title, hex, expectedLength) {
      let res;
      if (typeof hex === "string") {
        try {
          res = (0, utils_js_1.hexToBytes)(hex);
        } catch (e) {
          throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
        }
      } else if ((0, utils_js_1.isBytes)(hex)) {
        res = Uint8Array.from(hex);
      } else {
        throw new Error(title + " must be hex string or Uint8Array");
      }
      const len = res.length;
      if (typeof expectedLength === "number" && len !== expectedLength)
        throw new Error(title + " of length " + expectedLength + " expected, got " + len);
      return res;
    }
    function equalBytes(a, b) {
      if (a.length !== b.length)
        return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
      return diff === 0;
    }
    function copyBytes(bytes) {
      return Uint8Array.from(bytes);
    }
    function asciiToBytes(ascii) {
      return Uint8Array.from(ascii, (c, i) => {
        const charCode = c.charCodeAt(0);
        if (c.length !== 1 || charCode > 127) {
          throw new Error(`string contains non-ASCII character "${ascii[i]}" with code ${charCode} at position ${i}`);
        }
        return charCode;
      });
    }
    var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
    function inRange(n, min, max) {
      return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
    }
    function aInRange(title, n, min, max) {
      if (!inRange(n, min, max))
        throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
    }
    function bitLen(n) {
      let len;
      for (len = 0; n > _0n; n >>= _1n, len += 1)
        ;
      return len;
    }
    function bitGet(n, pos) {
      return n >> BigInt(pos) & _1n;
    }
    function bitSet(n, pos, value) {
      return n | (value ? _1n : _0n) << BigInt(pos);
    }
    var bitMask = (n) => (_1n << BigInt(n)) - _1n;
    exports$1.bitMask = bitMask;
    function createHmacDrbg(hashLen, qByteLen, hmacFn) {
      if (typeof hashLen !== "number" || hashLen < 2)
        throw new Error("hashLen must be a number");
      if (typeof qByteLen !== "number" || qByteLen < 2)
        throw new Error("qByteLen must be a number");
      if (typeof hmacFn !== "function")
        throw new Error("hmacFn must be a function");
      const u8n = (len) => new Uint8Array(len);
      const u8of = (byte) => Uint8Array.of(byte);
      let v = u8n(hashLen);
      let k = u8n(hashLen);
      let i = 0;
      const reset = () => {
        v.fill(1);
        k.fill(0);
        i = 0;
      };
      const h = (...b) => hmacFn(k, v, ...b);
      const reseed = (seed = u8n(0)) => {
        k = h(u8of(0), seed);
        v = h();
        if (seed.length === 0)
          return;
        k = h(u8of(1), seed);
        v = h();
      };
      const gen = () => {
        if (i++ >= 1e3)
          throw new Error("drbg: tried 1000 values");
        let len = 0;
        const out = [];
        while (len < qByteLen) {
          v = h();
          const sl = v.slice();
          out.push(sl);
          len += v.length;
        }
        return (0, utils_js_1.concatBytes)(...out);
      };
      const genUntil = (seed, pred) => {
        reset();
        reseed(seed);
        let res = void 0;
        while (!(res = pred(gen())))
          reseed();
        reset();
        return res;
      };
      return genUntil;
    }
    var validatorFns = {
      bigint: (val) => typeof val === "bigint",
      function: (val) => typeof val === "function",
      boolean: (val) => typeof val === "boolean",
      string: (val) => typeof val === "string",
      stringOrUint8Array: (val) => typeof val === "string" || (0, utils_js_1.isBytes)(val),
      isSafeInteger: (val) => Number.isSafeInteger(val),
      array: (val) => Array.isArray(val),
      field: (val, object) => object.Fp.isValid(val),
      hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
    };
    function validateObject(object, validators, optValidators = {}) {
      const checkField = (fieldName, type, isOptional) => {
        const checkVal = validatorFns[type];
        if (typeof checkVal !== "function")
          throw new Error("invalid validator function");
        const val = object[fieldName];
        if (isOptional && val === void 0)
          return;
        if (!checkVal(val, object)) {
          throw new Error("param " + String(fieldName) + " is invalid. Expected " + type + ", got " + val);
        }
      };
      for (const [fieldName, type] of Object.entries(validators))
        checkField(fieldName, type, false);
      for (const [fieldName, type] of Object.entries(optValidators))
        checkField(fieldName, type, true);
      return object;
    }
    function isHash(val) {
      return typeof val === "function" && Number.isSafeInteger(val.outputLen);
    }
    function _validateObject(object, fields, optFields = {}) {
      if (!object || typeof object !== "object")
        throw new Error("expected valid options object");
      function checkField(fieldName, expectedType, isOpt) {
        const val = object[fieldName];
        if (isOpt && val === void 0)
          return;
        const current = typeof val;
        if (current !== expectedType || val === null)
          throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
      }
      Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
      Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
    }
    var notImplemented = () => {
      throw new Error("not implemented");
    };
    exports$1.notImplemented = notImplemented;
    function memoized(fn) {
      const map = /* @__PURE__ */ new WeakMap();
      return (arg, ...args) => {
        const val = map.get(arg);
        if (val !== void 0)
          return val;
        const computed = fn(arg, ...args);
        map.set(arg, computed);
        return computed;
      };
    }
  }
});

// node_modules/@noble/curves/abstract/modular.js
var require_modular = __commonJS({
  "node_modules/@noble/curves/abstract/modular.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.isNegativeLE = void 0;
    exports$1.mod = mod;
    exports$1.pow = pow;
    exports$1.pow2 = pow2;
    exports$1.invert = invert;
    exports$1.tonelliShanks = tonelliShanks;
    exports$1.FpSqrt = FpSqrt;
    exports$1.validateField = validateField;
    exports$1.FpPow = FpPow;
    exports$1.FpInvertBatch = FpInvertBatch;
    exports$1.FpDiv = FpDiv;
    exports$1.FpLegendre = FpLegendre;
    exports$1.FpIsSquare = FpIsSquare;
    exports$1.nLength = nLength;
    exports$1.Field = Field;
    exports$1.FpSqrtOdd = FpSqrtOdd;
    exports$1.FpSqrtEven = FpSqrtEven;
    exports$1.hashToPrivateScalar = hashToPrivateScalar;
    exports$1.getFieldBytesLength = getFieldBytesLength;
    exports$1.getMinHashLength = getMinHashLength;
    exports$1.mapHashToField = mapHashToField;
    var utils_ts_1 = require_utils4();
    var _0n = BigInt(0);
    var _1n = BigInt(1);
    var _2n = /* @__PURE__ */ BigInt(2);
    var _3n = /* @__PURE__ */ BigInt(3);
    var _4n = /* @__PURE__ */ BigInt(4);
    var _5n = /* @__PURE__ */ BigInt(5);
    var _7n = /* @__PURE__ */ BigInt(7);
    var _8n = /* @__PURE__ */ BigInt(8);
    var _9n = /* @__PURE__ */ BigInt(9);
    var _16n = /* @__PURE__ */ BigInt(16);
    function mod(a, b) {
      const result = a % b;
      return result >= _0n ? result : b + result;
    }
    function pow(num, power, modulo) {
      return FpPow(Field(modulo), num, power);
    }
    function pow2(x, power, modulo) {
      let res = x;
      while (power-- > _0n) {
        res *= res;
        res %= modulo;
      }
      return res;
    }
    function invert(number, modulo) {
      if (number === _0n)
        throw new Error("invert: expected non-zero number");
      if (modulo <= _0n)
        throw new Error("invert: expected positive modulus, got " + modulo);
      let a = mod(number, modulo);
      let b = modulo;
      let x = _0n, u = _1n;
      while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        b = a, a = r, x = u, u = m;
      }
      const gcd = b;
      if (gcd !== _1n)
        throw new Error("invert: does not exist");
      return mod(x, modulo);
    }
    function assertIsSquare(Fp, root, n) {
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
    }
    function sqrt3mod4(Fp, n) {
      const p1div4 = (Fp.ORDER + _1n) / _4n;
      const root = Fp.pow(n, p1div4);
      assertIsSquare(Fp, root, n);
      return root;
    }
    function sqrt5mod8(Fp, n) {
      const p5div8 = (Fp.ORDER - _5n) / _8n;
      const n2 = Fp.mul(n, _2n);
      const v = Fp.pow(n2, p5div8);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      assertIsSquare(Fp, root, n);
      return root;
    }
    function sqrt9mod16(P) {
      const Fp_ = Field(P);
      const tn = tonelliShanks(P);
      const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
      const c2 = tn(Fp_, c1);
      const c3 = tn(Fp_, Fp_.neg(c1));
      const c4 = (P + _7n) / _16n;
      return (Fp, n) => {
        let tv1 = Fp.pow(n, c4);
        let tv2 = Fp.mul(tv1, c1);
        const tv3 = Fp.mul(tv1, c2);
        const tv4 = Fp.mul(tv1, c3);
        const e1 = Fp.eql(Fp.sqr(tv2), n);
        const e2 = Fp.eql(Fp.sqr(tv3), n);
        tv1 = Fp.cmov(tv1, tv2, e1);
        tv2 = Fp.cmov(tv4, tv3, e2);
        const e3 = Fp.eql(Fp.sqr(tv2), n);
        const root = Fp.cmov(tv1, tv2, e3);
        assertIsSquare(Fp, root, n);
        return root;
      };
    }
    function tonelliShanks(P) {
      if (P < _3n)
        throw new Error("sqrt is not defined for small field");
      let Q = P - _1n;
      let S = 0;
      while (Q % _2n === _0n) {
        Q /= _2n;
        S++;
      }
      let Z = _2n;
      const _Fp = Field(P);
      while (FpLegendre(_Fp, Z) === 1) {
        if (Z++ > 1e3)
          throw new Error("Cannot find square root: probably non-prime P");
      }
      if (S === 1)
        return sqrt3mod4;
      let cc = _Fp.pow(Z, Q);
      const Q1div2 = (Q + _1n) / _2n;
      return function tonelliSlow(Fp, n) {
        if (Fp.is0(n))
          return n;
        if (FpLegendre(Fp, n) !== 1)
          throw new Error("Cannot find square root");
        let M = S;
        let c = Fp.mul(Fp.ONE, cc);
        let t = Fp.pow(n, Q);
        let R = Fp.pow(n, Q1div2);
        while (!Fp.eql(t, Fp.ONE)) {
          if (Fp.is0(t))
            return Fp.ZERO;
          let i = 1;
          let t_tmp = Fp.sqr(t);
          while (!Fp.eql(t_tmp, Fp.ONE)) {
            i++;
            t_tmp = Fp.sqr(t_tmp);
            if (i === M)
              throw new Error("Cannot find square root");
          }
          const exponent = _1n << BigInt(M - i - 1);
          const b = Fp.pow(c, exponent);
          M = i;
          c = Fp.sqr(b);
          t = Fp.mul(t, c);
          R = Fp.mul(R, b);
        }
        return R;
      };
    }
    function FpSqrt(P) {
      if (P % _4n === _3n)
        return sqrt3mod4;
      if (P % _8n === _5n)
        return sqrt5mod8;
      if (P % _16n === _9n)
        return sqrt9mod16(P);
      return tonelliShanks(P);
    }
    var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n) === _1n;
    exports$1.isNegativeLE = isNegativeLE;
    var FIELD_FIELDS = [
      "create",
      "isValid",
      "is0",
      "neg",
      "inv",
      "sqrt",
      "sqr",
      "eql",
      "add",
      "sub",
      "mul",
      "pow",
      "div",
      "addN",
      "subN",
      "mulN",
      "sqrN"
    ];
    function validateField(field) {
      const initial = {
        ORDER: "bigint",
        MASK: "bigint",
        BYTES: "number",
        BITS: "number"
      };
      const opts = FIELD_FIELDS.reduce((map, val) => {
        map[val] = "function";
        return map;
      }, initial);
      (0, utils_ts_1._validateObject)(field, opts);
      return field;
    }
    function FpPow(Fp, num, power) {
      if (power < _0n)
        throw new Error("invalid exponent, negatives unsupported");
      if (power === _0n)
        return Fp.ONE;
      if (power === _1n)
        return num;
      let p = Fp.ONE;
      let d = num;
      while (power > _0n) {
        if (power & _1n)
          p = Fp.mul(p, d);
        d = Fp.sqr(d);
        power >>= _1n;
      }
      return p;
    }
    function FpInvertBatch(Fp, nums, passZero = false) {
      const inverted = new Array(nums.length).fill(passZero ? Fp.ZERO : void 0);
      const multipliedAcc = nums.reduce((acc, num, i) => {
        if (Fp.is0(num))
          return acc;
        inverted[i] = acc;
        return Fp.mul(acc, num);
      }, Fp.ONE);
      const invertedAcc = Fp.inv(multipliedAcc);
      nums.reduceRight((acc, num, i) => {
        if (Fp.is0(num))
          return acc;
        inverted[i] = Fp.mul(acc, inverted[i]);
        return Fp.mul(acc, num);
      }, invertedAcc);
      return inverted;
    }
    function FpDiv(Fp, lhs, rhs) {
      return Fp.mul(lhs, typeof rhs === "bigint" ? invert(rhs, Fp.ORDER) : Fp.inv(rhs));
    }
    function FpLegendre(Fp, n) {
      const p1mod2 = (Fp.ORDER - _1n) / _2n;
      const powered = Fp.pow(n, p1mod2);
      const yes = Fp.eql(powered, Fp.ONE);
      const zero = Fp.eql(powered, Fp.ZERO);
      const no = Fp.eql(powered, Fp.neg(Fp.ONE));
      if (!yes && !zero && !no)
        throw new Error("invalid Legendre symbol result");
      return yes ? 1 : zero ? 0 : -1;
    }
    function FpIsSquare(Fp, n) {
      const l = FpLegendre(Fp, n);
      return l === 1;
    }
    function nLength(n, nBitLength) {
      if (nBitLength !== void 0)
        (0, utils_ts_1.anumber)(nBitLength);
      const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
      const nByteLength = Math.ceil(_nBitLength / 8);
      return { nBitLength: _nBitLength, nByteLength };
    }
    function Field(ORDER, bitLenOrOpts, isLE = false, opts = {}) {
      if (ORDER <= _0n)
        throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
      let _nbitLength = void 0;
      let _sqrt = void 0;
      let modFromBytes = false;
      let allowedLengths = void 0;
      if (typeof bitLenOrOpts === "object" && bitLenOrOpts != null) {
        if (opts.sqrt || isLE)
          throw new Error("cannot specify opts in two arguments");
        const _opts = bitLenOrOpts;
        if (_opts.BITS)
          _nbitLength = _opts.BITS;
        if (_opts.sqrt)
          _sqrt = _opts.sqrt;
        if (typeof _opts.isLE === "boolean")
          isLE = _opts.isLE;
        if (typeof _opts.modFromBytes === "boolean")
          modFromBytes = _opts.modFromBytes;
        allowedLengths = _opts.allowedLengths;
      } else {
        if (typeof bitLenOrOpts === "number")
          _nbitLength = bitLenOrOpts;
        if (opts.sqrt)
          _sqrt = opts.sqrt;
      }
      const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, _nbitLength);
      if (BYTES > 2048)
        throw new Error("invalid field: expected ORDER of <= 2048 bytes");
      let sqrtP;
      const f = Object.freeze({
        ORDER,
        isLE,
        BITS,
        BYTES,
        MASK: (0, utils_ts_1.bitMask)(BITS),
        ZERO: _0n,
        ONE: _1n,
        allowedLengths,
        create: (num) => mod(num, ORDER),
        isValid: (num) => {
          if (typeof num !== "bigint")
            throw new Error("invalid field element: expected bigint, got " + typeof num);
          return _0n <= num && num < ORDER;
        },
        is0: (num) => num === _0n,
        // is valid and invertible
        isValidNot0: (num) => !f.is0(num) && f.isValid(num),
        isOdd: (num) => (num & _1n) === _1n,
        neg: (num) => mod(-num, ORDER),
        eql: (lhs, rhs) => lhs === rhs,
        sqr: (num) => mod(num * num, ORDER),
        add: (lhs, rhs) => mod(lhs + rhs, ORDER),
        sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
        mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
        pow: (num, power) => FpPow(f, num, power),
        div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
        // Same as above, but doesn't normalize
        sqrN: (num) => num * num,
        addN: (lhs, rhs) => lhs + rhs,
        subN: (lhs, rhs) => lhs - rhs,
        mulN: (lhs, rhs) => lhs * rhs,
        inv: (num) => invert(num, ORDER),
        sqrt: _sqrt || ((n) => {
          if (!sqrtP)
            sqrtP = FpSqrt(ORDER);
          return sqrtP(f, n);
        }),
        toBytes: (num) => isLE ? (0, utils_ts_1.numberToBytesLE)(num, BYTES) : (0, utils_ts_1.numberToBytesBE)(num, BYTES),
        fromBytes: (bytes, skipValidation = true) => {
          if (allowedLengths) {
            if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
              throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
            }
            const padded = new Uint8Array(BYTES);
            padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
            bytes = padded;
          }
          if (bytes.length !== BYTES)
            throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
          let scalar = isLE ? (0, utils_ts_1.bytesToNumberLE)(bytes) : (0, utils_ts_1.bytesToNumberBE)(bytes);
          if (modFromBytes)
            scalar = mod(scalar, ORDER);
          if (!skipValidation) {
            if (!f.isValid(scalar))
              throw new Error("invalid field element: outside of range 0..ORDER");
          }
          return scalar;
        },
        // TODO: we don't need it here, move out to separate fn
        invertBatch: (lst) => FpInvertBatch(f, lst),
        // We can't move this out because Fp6, Fp12 implement it
        // and it's unclear what to return in there.
        cmov: (a, b, c) => c ? b : a
      });
      return Object.freeze(f);
    }
    function FpSqrtOdd(Fp, elm) {
      if (!Fp.isOdd)
        throw new Error("Field doesn't have isOdd");
      const root = Fp.sqrt(elm);
      return Fp.isOdd(root) ? root : Fp.neg(root);
    }
    function FpSqrtEven(Fp, elm) {
      if (!Fp.isOdd)
        throw new Error("Field doesn't have isOdd");
      const root = Fp.sqrt(elm);
      return Fp.isOdd(root) ? Fp.neg(root) : root;
    }
    function hashToPrivateScalar(hash2, groupOrder, isLE = false) {
      hash2 = (0, utils_ts_1.ensureBytes)("privateHash", hash2);
      const hashLen = hash2.length;
      const minLen = nLength(groupOrder).nByteLength + 8;
      if (minLen < 24 || hashLen < minLen || hashLen > 1024)
        throw new Error("hashToPrivateScalar: expected " + minLen + "-1024 bytes of input, got " + hashLen);
      const num = isLE ? (0, utils_ts_1.bytesToNumberLE)(hash2) : (0, utils_ts_1.bytesToNumberBE)(hash2);
      return mod(num, groupOrder - _1n) + _1n;
    }
    function getFieldBytesLength(fieldOrder) {
      if (typeof fieldOrder !== "bigint")
        throw new Error("field order must be bigint");
      const bitLength = fieldOrder.toString(2).length;
      return Math.ceil(bitLength / 8);
    }
    function getMinHashLength(fieldOrder) {
      const length = getFieldBytesLength(fieldOrder);
      return length + Math.ceil(length / 2);
    }
    function mapHashToField(key, fieldOrder, isLE = false) {
      const len = key.length;
      const fieldLen = getFieldBytesLength(fieldOrder);
      const minLen = getMinHashLength(fieldOrder);
      if (len < 16 || len < minLen || len > 1024)
        throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
      const num = isLE ? (0, utils_ts_1.bytesToNumberLE)(key) : (0, utils_ts_1.bytesToNumberBE)(key);
      const reduced = mod(num, fieldOrder - _1n) + _1n;
      return isLE ? (0, utils_ts_1.numberToBytesLE)(reduced, fieldLen) : (0, utils_ts_1.numberToBytesBE)(reduced, fieldLen);
    }
  }
});

// node_modules/@noble/curves/abstract/curve.js
var require_curve = __commonJS({
  "node_modules/@noble/curves/abstract/curve.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.wNAF = void 0;
    exports$1.negateCt = negateCt;
    exports$1.normalizeZ = normalizeZ;
    exports$1.mulEndoUnsafe = mulEndoUnsafe;
    exports$1.pippenger = pippenger;
    exports$1.precomputeMSMUnsafe = precomputeMSMUnsafe;
    exports$1.validateBasic = validateBasic;
    exports$1._createCurveFields = _createCurveFields;
    var utils_ts_1 = require_utils4();
    var modular_ts_1 = require_modular();
    var _0n = BigInt(0);
    var _1n = BigInt(1);
    function negateCt(condition, item) {
      const neg = item.negate();
      return condition ? neg : item;
    }
    function normalizeZ(c, points) {
      const invertedZs = (0, modular_ts_1.FpInvertBatch)(c.Fp, points.map((p) => p.Z));
      return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
    }
    function validateW(W, bits) {
      if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
        throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
    }
    function calcWOpts(W, scalarBits) {
      validateW(W, scalarBits);
      const windows = Math.ceil(scalarBits / W) + 1;
      const windowSize = 2 ** (W - 1);
      const maxNumber = 2 ** W;
      const mask = (0, utils_ts_1.bitMask)(W);
      const shiftBy = BigInt(W);
      return { windows, windowSize, mask, maxNumber, shiftBy };
    }
    function calcOffsets(n, window, wOpts) {
      const { windowSize, mask, maxNumber, shiftBy } = wOpts;
      let wbits = Number(n & mask);
      let nextN = n >> shiftBy;
      if (wbits > windowSize) {
        wbits -= maxNumber;
        nextN += _1n;
      }
      const offsetStart = window * windowSize;
      const offset = offsetStart + Math.abs(wbits) - 1;
      const isZero = wbits === 0;
      const isNeg = wbits < 0;
      const isNegF = window % 2 !== 0;
      const offsetF = offsetStart;
      return { nextN, offset, isZero, isNeg, isNegF, offsetF };
    }
    function validateMSMPoints(points, c) {
      if (!Array.isArray(points))
        throw new Error("array expected");
      points.forEach((p, i) => {
        if (!(p instanceof c))
          throw new Error("invalid point at index " + i);
      });
    }
    function validateMSMScalars(scalars, field) {
      if (!Array.isArray(scalars))
        throw new Error("array of scalars expected");
      scalars.forEach((s, i) => {
        if (!field.isValid(s))
          throw new Error("invalid scalar at index " + i);
      });
    }
    var pointPrecomputes = /* @__PURE__ */ new WeakMap();
    var pointWindowSizes = /* @__PURE__ */ new WeakMap();
    function getW(P) {
      return pointWindowSizes.get(P) || 1;
    }
    function assert0(n) {
      if (n !== _0n)
        throw new Error("invalid wNAF");
    }
    var wNAF = class {
      // Parametrized with a given Point class (not individual point)
      constructor(Point, bits) {
        this.BASE = Point.BASE;
        this.ZERO = Point.ZERO;
        this.Fn = Point.Fn;
        this.bits = bits;
      }
      // non-const time multiplication ladder
      _unsafeLadder(elm, n, p = this.ZERO) {
        let d = elm;
        while (n > _0n) {
          if (n & _1n)
            p = p.add(d);
          d = d.double();
          n >>= _1n;
        }
        return p;
      }
      /**
       * Creates a wNAF precomputation window. Used for caching.
       * Default window size is set by `utils.precompute()` and is equal to 8.
       * Number of precomputed points depends on the curve size:
       * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
       * - 𝑊 is the window size
       * - 𝑛 is the bitlength of the curve order.
       * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
       * @param point Point instance
       * @param W window size
       * @returns precomputed point tables flattened to a single array
       */
      precomputeWindow(point, W) {
        const { windows, windowSize } = calcWOpts(W, this.bits);
        const points = [];
        let p = point;
        let base = p;
        for (let window = 0; window < windows; window++) {
          base = p;
          points.push(base);
          for (let i = 1; i < windowSize; i++) {
            base = base.add(p);
            points.push(base);
          }
          p = base.double();
        }
        return points;
      }
      /**
       * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
       * More compact implementation:
       * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
       * @returns real and fake (for const-time) points
       */
      wNAF(W, precomputes, n) {
        if (!this.Fn.isValid(n))
          throw new Error("invalid scalar");
        let p = this.ZERO;
        let f = this.BASE;
        const wo = calcWOpts(W, this.bits);
        for (let window = 0; window < wo.windows; window++) {
          const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
          n = nextN;
          if (isZero) {
            f = f.add(negateCt(isNegF, precomputes[offsetF]));
          } else {
            p = p.add(negateCt(isNeg, precomputes[offset]));
          }
        }
        assert0(n);
        return { p, f };
      }
      /**
       * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
       * @param acc accumulator point to add result of multiplication
       * @returns point
       */
      wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
        const wo = calcWOpts(W, this.bits);
        for (let window = 0; window < wo.windows; window++) {
          if (n === _0n)
            break;
          const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
          n = nextN;
          if (isZero) {
            continue;
          } else {
            const item = precomputes[offset];
            acc = acc.add(isNeg ? item.negate() : item);
          }
        }
        assert0(n);
        return acc;
      }
      getPrecomputes(W, point, transform) {
        let comp = pointPrecomputes.get(point);
        if (!comp) {
          comp = this.precomputeWindow(point, W);
          if (W !== 1) {
            if (typeof transform === "function")
              comp = transform(comp);
            pointPrecomputes.set(point, comp);
          }
        }
        return comp;
      }
      cached(point, scalar, transform) {
        const W = getW(point);
        return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
      }
      unsafe(point, scalar, transform, prev) {
        const W = getW(point);
        if (W === 1)
          return this._unsafeLadder(point, scalar, prev);
        return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
      }
      // We calculate precomputes for elliptic curve point multiplication
      // using windowed method. This specifies window size and
      // stores precomputed values. Usually only base point would be precomputed.
      createCache(P, W) {
        validateW(W, this.bits);
        pointWindowSizes.set(P, W);
        pointPrecomputes.delete(P);
      }
      hasCache(elm) {
        return getW(elm) !== 1;
      }
    };
    exports$1.wNAF = wNAF;
    function mulEndoUnsafe(Point, point, k1, k2) {
      let acc = point;
      let p1 = Point.ZERO;
      let p2 = Point.ZERO;
      while (k1 > _0n || k2 > _0n) {
        if (k1 & _1n)
          p1 = p1.add(acc);
        if (k2 & _1n)
          p2 = p2.add(acc);
        acc = acc.double();
        k1 >>= _1n;
        k2 >>= _1n;
      }
      return { p1, p2 };
    }
    function pippenger(c, fieldN, points, scalars) {
      validateMSMPoints(points, c);
      validateMSMScalars(scalars, fieldN);
      const plength = points.length;
      const slength = scalars.length;
      if (plength !== slength)
        throw new Error("arrays of points and scalars must have equal length");
      const zero = c.ZERO;
      const wbits = (0, utils_ts_1.bitLen)(BigInt(plength));
      let windowSize = 1;
      if (wbits > 12)
        windowSize = wbits - 3;
      else if (wbits > 4)
        windowSize = wbits - 2;
      else if (wbits > 0)
        windowSize = 2;
      const MASK = (0, utils_ts_1.bitMask)(windowSize);
      const buckets = new Array(Number(MASK) + 1).fill(zero);
      const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
      let sum = zero;
      for (let i = lastBits; i >= 0; i -= windowSize) {
        buckets.fill(zero);
        for (let j = 0; j < slength; j++) {
          const scalar = scalars[j];
          const wbits2 = Number(scalar >> BigInt(i) & MASK);
          buckets[wbits2] = buckets[wbits2].add(points[j]);
        }
        let resI = zero;
        for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
          sumI = sumI.add(buckets[j]);
          resI = resI.add(sumI);
        }
        sum = sum.add(resI);
        if (i !== 0)
          for (let j = 0; j < windowSize; j++)
            sum = sum.double();
      }
      return sum;
    }
    function precomputeMSMUnsafe(c, fieldN, points, windowSize) {
      validateW(windowSize, fieldN.BITS);
      validateMSMPoints(points, c);
      const zero = c.ZERO;
      const tableSize = 2 ** windowSize - 1;
      const chunks = Math.ceil(fieldN.BITS / windowSize);
      const MASK = (0, utils_ts_1.bitMask)(windowSize);
      const tables = points.map((p) => {
        const res = [];
        for (let i = 0, acc = p; i < tableSize; i++) {
          res.push(acc);
          acc = acc.add(p);
        }
        return res;
      });
      return (scalars) => {
        validateMSMScalars(scalars, fieldN);
        if (scalars.length > points.length)
          throw new Error("array of scalars must be smaller than array of points");
        let res = zero;
        for (let i = 0; i < chunks; i++) {
          if (res !== zero)
            for (let j = 0; j < windowSize; j++)
              res = res.double();
          const shiftBy = BigInt(chunks * windowSize - (i + 1) * windowSize);
          for (let j = 0; j < scalars.length; j++) {
            const n = scalars[j];
            const curr = Number(n >> shiftBy & MASK);
            if (!curr)
              continue;
            res = res.add(tables[j][curr - 1]);
          }
        }
        return res;
      };
    }
    function validateBasic(curve) {
      (0, modular_ts_1.validateField)(curve.Fp);
      (0, utils_ts_1.validateObject)(curve, {
        n: "bigint",
        h: "bigint",
        Gx: "field",
        Gy: "field"
      }, {
        nBitLength: "isSafeInteger",
        nByteLength: "isSafeInteger"
      });
      return Object.freeze({
        ...(0, modular_ts_1.nLength)(curve.n, curve.nBitLength),
        ...curve,
        ...{ p: curve.Fp.ORDER }
      });
    }
    function createField(order, field, isLE) {
      if (field) {
        if (field.ORDER !== order)
          throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
        (0, modular_ts_1.validateField)(field);
        return field;
      } else {
        return (0, modular_ts_1.Field)(order, { isLE });
      }
    }
    function _createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
      if (FpFnLE === void 0)
        FpFnLE = type === "edwards";
      if (!CURVE || typeof CURVE !== "object")
        throw new Error(`expected valid ${type} CURVE object`);
      for (const p of ["p", "n", "h"]) {
        const val = CURVE[p];
        if (!(typeof val === "bigint" && val > _0n))
          throw new Error(`CURVE.${p} must be positive bigint`);
      }
      const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
      const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
      const _b = type === "weierstrass" ? "b" : "d";
      const params = ["Gx", "Gy", "a", _b];
      for (const p of params) {
        if (!Fp.isValid(CURVE[p]))
          throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
      }
      CURVE = Object.freeze(Object.assign({}, CURVE));
      return { CURVE, Fp, Fn };
    }
  }
});

// node_modules/@noble/curves/abstract/weierstrass.js
var require_weierstrass = __commonJS({
  "node_modules/@noble/curves/abstract/weierstrass.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.DER = exports$1.DERErr = void 0;
    exports$1._splitEndoScalar = _splitEndoScalar;
    exports$1._normFnElement = _normFnElement;
    exports$1.weierstrassN = weierstrassN;
    exports$1.SWUFpSqrtRatio = SWUFpSqrtRatio;
    exports$1.mapToCurveSimpleSWU = mapToCurveSimpleSWU;
    exports$1.ecdh = ecdh;
    exports$1.ecdsa = ecdsa;
    exports$1.weierstrassPoints = weierstrassPoints;
    exports$1._legacyHelperEquat = _legacyHelperEquat;
    exports$1.weierstrass = weierstrass;
    var hmac_js_1 = require_hmac();
    var utils_1 = require_utils();
    var utils_ts_1 = require_utils4();
    var curve_ts_1 = require_curve();
    var modular_ts_1 = require_modular();
    var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n) / den;
    function _splitEndoScalar(k, basis, n) {
      const [[a1, b1], [a2, b2]] = basis;
      const c1 = divNearest(b2 * k, n);
      const c2 = divNearest(-b1 * k, n);
      let k1 = k - c1 * a1 - c2 * a2;
      let k2 = -c1 * b1 - c2 * b2;
      const k1neg = k1 < _0n;
      const k2neg = k2 < _0n;
      if (k1neg)
        k1 = -k1;
      if (k2neg)
        k2 = -k2;
      const MAX_NUM = (0, utils_ts_1.bitMask)(Math.ceil((0, utils_ts_1.bitLen)(n) / 2)) + _1n;
      if (k1 < _0n || k1 >= MAX_NUM || k2 < _0n || k2 >= MAX_NUM) {
        throw new Error("splitScalar (endomorphism): failed, k=" + k);
      }
      return { k1neg, k1, k2neg, k2 };
    }
    function validateSigFormat(format) {
      if (!["compact", "recovered", "der"].includes(format))
        throw new Error('Signature format must be "compact", "recovered", or "der"');
      return format;
    }
    function validateSigOpts(opts, def) {
      const optsn = {};
      for (let optName of Object.keys(def)) {
        optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
      }
      (0, utils_ts_1._abool2)(optsn.lowS, "lowS");
      (0, utils_ts_1._abool2)(optsn.prehash, "prehash");
      if (optsn.format !== void 0)
        validateSigFormat(optsn.format);
      return optsn;
    }
    var DERErr = class extends Error {
      constructor(m = "") {
        super(m);
      }
    };
    exports$1.DERErr = DERErr;
    exports$1.DER = {
      // asn.1 DER encoding utils
      Err: DERErr,
      // Basic building block is TLV (Tag-Length-Value)
      _tlv: {
        encode: (tag, data) => {
          const { Err: E } = exports$1.DER;
          if (tag < 0 || tag > 256)
            throw new E("tlv.encode: wrong tag");
          if (data.length & 1)
            throw new E("tlv.encode: unpadded data");
          const dataLen = data.length / 2;
          const len = (0, utils_ts_1.numberToHexUnpadded)(dataLen);
          if (len.length / 2 & 128)
            throw new E("tlv.encode: long form length too big");
          const lenLen = dataLen > 127 ? (0, utils_ts_1.numberToHexUnpadded)(len.length / 2 | 128) : "";
          const t = (0, utils_ts_1.numberToHexUnpadded)(tag);
          return t + lenLen + len + data;
        },
        // v - value, l - left bytes (unparsed)
        decode(tag, data) {
          const { Err: E } = exports$1.DER;
          let pos = 0;
          if (tag < 0 || tag > 256)
            throw new E("tlv.encode: wrong tag");
          if (data.length < 2 || data[pos++] !== tag)
            throw new E("tlv.decode: wrong tlv");
          const first = data[pos++];
          const isLong = !!(first & 128);
          let length = 0;
          if (!isLong)
            length = first;
          else {
            const lenLen = first & 127;
            if (!lenLen)
              throw new E("tlv.decode(long): indefinite length not supported");
            if (lenLen > 4)
              throw new E("tlv.decode(long): byte length is too big");
            const lengthBytes = data.subarray(pos, pos + lenLen);
            if (lengthBytes.length !== lenLen)
              throw new E("tlv.decode: length bytes not complete");
            if (lengthBytes[0] === 0)
              throw new E("tlv.decode(long): zero leftmost byte");
            for (const b of lengthBytes)
              length = length << 8 | b;
            pos += lenLen;
            if (length < 128)
              throw new E("tlv.decode(long): not minimal encoding");
          }
          const v = data.subarray(pos, pos + length);
          if (v.length !== length)
            throw new E("tlv.decode: wrong value length");
          return { v, l: data.subarray(pos + length) };
        }
      },
      // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
      // since we always use positive integers here. It must always be empty:
      // - add zero byte if exists
      // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
      _int: {
        encode(num) {
          const { Err: E } = exports$1.DER;
          if (num < _0n)
            throw new E("integer: negative integers are not allowed");
          let hex = (0, utils_ts_1.numberToHexUnpadded)(num);
          if (Number.parseInt(hex[0], 16) & 8)
            hex = "00" + hex;
          if (hex.length & 1)
            throw new E("unexpected DER parsing assertion: unpadded hex");
          return hex;
        },
        decode(data) {
          const { Err: E } = exports$1.DER;
          if (data[0] & 128)
            throw new E("invalid signature integer: negative");
          if (data[0] === 0 && !(data[1] & 128))
            throw new E("invalid signature integer: unnecessary leading zero");
          return (0, utils_ts_1.bytesToNumberBE)(data);
        }
      },
      toSig(hex) {
        const { Err: E, _int: int, _tlv: tlv } = exports$1.DER;
        const data = (0, utils_ts_1.ensureBytes)("signature", hex);
        const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
        if (seqLeftBytes.length)
          throw new E("invalid signature: left bytes after parsing");
        const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
        const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
        if (sLeftBytes.length)
          throw new E("invalid signature: left bytes after parsing");
        return { r: int.decode(rBytes), s: int.decode(sBytes) };
      },
      hexFromSig(sig) {
        const { _tlv: tlv, _int: int } = exports$1.DER;
        const rs = tlv.encode(2, int.encode(sig.r));
        const ss = tlv.encode(2, int.encode(sig.s));
        const seq = rs + ss;
        return tlv.encode(48, seq);
      }
    };
    var _0n = BigInt(0);
    var _1n = BigInt(1);
    var _2n = BigInt(2);
    var _3n = BigInt(3);
    var _4n = BigInt(4);
    function _normFnElement(Fn, key) {
      const { BYTES: expected } = Fn;
      let num;
      if (typeof key === "bigint") {
        num = key;
      } else {
        let bytes = (0, utils_ts_1.ensureBytes)("private key", key);
        try {
          num = Fn.fromBytes(bytes);
        } catch (error) {
          throw new Error(`invalid private key: expected ui8a of size ${expected}, got ${typeof key}`);
        }
      }
      if (!Fn.isValidNot0(num))
        throw new Error("invalid private key: out of range [1..N-1]");
      return num;
    }
    function weierstrassN(params, extraOpts = {}) {
      const validated = (0, curve_ts_1._createCurveFields)("weierstrass", params, extraOpts);
      const { Fp, Fn } = validated;
      let CURVE = validated.CURVE;
      const { h: cofactor, n: CURVE_ORDER } = CURVE;
      (0, utils_ts_1._validateObject)(extraOpts, {}, {
        allowInfinityPoint: "boolean",
        clearCofactor: "function",
        isTorsionFree: "function",
        fromBytes: "function",
        toBytes: "function",
        endo: "object",
        wrapPrivateKey: "boolean"
      });
      const { endo } = extraOpts;
      if (endo) {
        if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
          throw new Error('invalid endo: expected "beta": bigint and "basises": array');
        }
      }
      const lengths = getWLengths(Fp, Fn);
      function assertCompressionIsSupported() {
        if (!Fp.isOdd)
          throw new Error("compression is not supported: Field does not have .isOdd()");
      }
      function pointToBytes(_c, point, isCompressed) {
        const { x, y } = point.toAffine();
        const bx = Fp.toBytes(x);
        (0, utils_ts_1._abool2)(isCompressed, "isCompressed");
        if (isCompressed) {
          assertCompressionIsSupported();
          const hasEvenY = !Fp.isOdd(y);
          return (0, utils_ts_1.concatBytes)(pprefix(hasEvenY), bx);
        } else {
          return (0, utils_ts_1.concatBytes)(Uint8Array.of(4), bx, Fp.toBytes(y));
        }
      }
      function pointFromBytes(bytes) {
        (0, utils_ts_1._abytes2)(bytes, void 0, "Point");
        const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
        const length = bytes.length;
        const head = bytes[0];
        const tail = bytes.subarray(1);
        if (length === comp && (head === 2 || head === 3)) {
          const x = Fp.fromBytes(tail);
          if (!Fp.isValid(x))
            throw new Error("bad point: is not on curve, wrong x");
          const y2 = weierstrassEquation(x);
          let y;
          try {
            y = Fp.sqrt(y2);
          } catch (sqrtError) {
            const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
            throw new Error("bad point: is not on curve, sqrt error" + err);
          }
          assertCompressionIsSupported();
          const isYOdd = Fp.isOdd(y);
          const isHeadOdd = (head & 1) === 1;
          if (isHeadOdd !== isYOdd)
            y = Fp.neg(y);
          return { x, y };
        } else if (length === uncomp && head === 4) {
          const L = Fp.BYTES;
          const x = Fp.fromBytes(tail.subarray(0, L));
          const y = Fp.fromBytes(tail.subarray(L, L * 2));
          if (!isValidXY(x, y))
            throw new Error("bad point: is not on curve");
          return { x, y };
        } else {
          throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
        }
      }
      const encodePoint = extraOpts.toBytes || pointToBytes;
      const decodePoint = extraOpts.fromBytes || pointFromBytes;
      function weierstrassEquation(x) {
        const x2 = Fp.sqr(x);
        const x3 = Fp.mul(x2, x);
        return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
      }
      function isValidXY(x, y) {
        const left = Fp.sqr(y);
        const right = weierstrassEquation(x);
        return Fp.eql(left, right);
      }
      if (!isValidXY(CURVE.Gx, CURVE.Gy))
        throw new Error("bad curve params: generator point");
      const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n), _4n);
      const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
      if (Fp.is0(Fp.add(_4a3, _27b2)))
        throw new Error("bad curve params: a or b");
      function acoord(title, n, banZero = false) {
        if (!Fp.isValid(n) || banZero && Fp.is0(n))
          throw new Error(`bad point coordinate ${title}`);
        return n;
      }
      function aprjpoint(other) {
        if (!(other instanceof Point))
          throw new Error("ProjectivePoint expected");
      }
      function splitEndoScalarN(k) {
        if (!endo || !endo.basises)
          throw new Error("no endo");
        return _splitEndoScalar(k, endo.basises, Fn.ORDER);
      }
      const toAffineMemo = (0, utils_ts_1.memoized)((p, iz) => {
        const { X, Y, Z } = p;
        if (Fp.eql(Z, Fp.ONE))
          return { x: X, y: Y };
        const is0 = p.is0();
        if (iz == null)
          iz = is0 ? Fp.ONE : Fp.inv(Z);
        const x = Fp.mul(X, iz);
        const y = Fp.mul(Y, iz);
        const zz = Fp.mul(Z, iz);
        if (is0)
          return { x: Fp.ZERO, y: Fp.ZERO };
        if (!Fp.eql(zz, Fp.ONE))
          throw new Error("invZ was invalid");
        return { x, y };
      });
      const assertValidMemo = (0, utils_ts_1.memoized)((p) => {
        if (p.is0()) {
          if (extraOpts.allowInfinityPoint && !Fp.is0(p.Y))
            return;
          throw new Error("bad point: ZERO");
        }
        const { x, y } = p.toAffine();
        if (!Fp.isValid(x) || !Fp.isValid(y))
          throw new Error("bad point: x or y not field elements");
        if (!isValidXY(x, y))
          throw new Error("bad point: equation left != right");
        if (!p.isTorsionFree())
          throw new Error("bad point: not in prime-order subgroup");
        return true;
      });
      function finishEndo(endoBeta, k1p, k2p, k1neg, k2neg) {
        k2p = new Point(Fp.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
        k1p = (0, curve_ts_1.negateCt)(k1neg, k1p);
        k2p = (0, curve_ts_1.negateCt)(k2neg, k2p);
        return k1p.add(k2p);
      }
      class Point {
        /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
        constructor(X, Y, Z) {
          this.X = acoord("x", X);
          this.Y = acoord("y", Y, true);
          this.Z = acoord("z", Z);
          Object.freeze(this);
        }
        static CURVE() {
          return CURVE;
        }
        /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
        static fromAffine(p) {
          const { x, y } = p || {};
          if (!p || !Fp.isValid(x) || !Fp.isValid(y))
            throw new Error("invalid affine point");
          if (p instanceof Point)
            throw new Error("projective point not allowed");
          if (Fp.is0(x) && Fp.is0(y))
            return Point.ZERO;
          return new Point(x, y, Fp.ONE);
        }
        static fromBytes(bytes) {
          const P = Point.fromAffine(decodePoint((0, utils_ts_1._abytes2)(bytes, void 0, "point")));
          P.assertValidity();
          return P;
        }
        static fromHex(hex) {
          return Point.fromBytes((0, utils_ts_1.ensureBytes)("pointHex", hex));
        }
        get x() {
          return this.toAffine().x;
        }
        get y() {
          return this.toAffine().y;
        }
        /**
         *
         * @param windowSize
         * @param isLazy true will defer table computation until the first multiplication
         * @returns
         */
        precompute(windowSize = 8, isLazy = true) {
          wnaf.createCache(this, windowSize);
          if (!isLazy)
            this.multiply(_3n);
          return this;
        }
        // TODO: return `this`
        /** A point on curve is valid if it conforms to equation. */
        assertValidity() {
          assertValidMemo(this);
        }
        hasEvenY() {
          const { y } = this.toAffine();
          if (!Fp.isOdd)
            throw new Error("Field doesn't support isOdd");
          return !Fp.isOdd(y);
        }
        /** Compare one point to another. */
        equals(other) {
          aprjpoint(other);
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const { X: X2, Y: Y2, Z: Z2 } = other;
          const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
          const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
          return U1 && U2;
        }
        /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
        negate() {
          return new Point(this.X, Fp.neg(this.Y), this.Z);
        }
        // Renes-Costello-Batina exception-free doubling formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 3
        // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
        double() {
          const { a, b } = CURVE;
          const b3 = Fp.mul(b, _3n);
          const { X: X1, Y: Y1, Z: Z1 } = this;
          let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
          let t0 = Fp.mul(X1, X1);
          let t1 = Fp.mul(Y1, Y1);
          let t2 = Fp.mul(Z1, Z1);
          let t3 = Fp.mul(X1, Y1);
          t3 = Fp.add(t3, t3);
          Z3 = Fp.mul(X1, Z1);
          Z3 = Fp.add(Z3, Z3);
          X3 = Fp.mul(a, Z3);
          Y3 = Fp.mul(b3, t2);
          Y3 = Fp.add(X3, Y3);
          X3 = Fp.sub(t1, Y3);
          Y3 = Fp.add(t1, Y3);
          Y3 = Fp.mul(X3, Y3);
          X3 = Fp.mul(t3, X3);
          Z3 = Fp.mul(b3, Z3);
          t2 = Fp.mul(a, t2);
          t3 = Fp.sub(t0, t2);
          t3 = Fp.mul(a, t3);
          t3 = Fp.add(t3, Z3);
          Z3 = Fp.add(t0, t0);
          t0 = Fp.add(Z3, t0);
          t0 = Fp.add(t0, t2);
          t0 = Fp.mul(t0, t3);
          Y3 = Fp.add(Y3, t0);
          t2 = Fp.mul(Y1, Z1);
          t2 = Fp.add(t2, t2);
          t0 = Fp.mul(t2, t3);
          X3 = Fp.sub(X3, t0);
          Z3 = Fp.mul(t2, t1);
          Z3 = Fp.add(Z3, Z3);
          Z3 = Fp.add(Z3, Z3);
          return new Point(X3, Y3, Z3);
        }
        // Renes-Costello-Batina exception-free addition formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 1
        // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
        add(other) {
          aprjpoint(other);
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const { X: X2, Y: Y2, Z: Z2 } = other;
          let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
          const a = CURVE.a;
          const b3 = Fp.mul(CURVE.b, _3n);
          let t0 = Fp.mul(X1, X2);
          let t1 = Fp.mul(Y1, Y2);
          let t2 = Fp.mul(Z1, Z2);
          let t3 = Fp.add(X1, Y1);
          let t4 = Fp.add(X2, Y2);
          t3 = Fp.mul(t3, t4);
          t4 = Fp.add(t0, t1);
          t3 = Fp.sub(t3, t4);
          t4 = Fp.add(X1, Z1);
          let t5 = Fp.add(X2, Z2);
          t4 = Fp.mul(t4, t5);
          t5 = Fp.add(t0, t2);
          t4 = Fp.sub(t4, t5);
          t5 = Fp.add(Y1, Z1);
          X3 = Fp.add(Y2, Z2);
          t5 = Fp.mul(t5, X3);
          X3 = Fp.add(t1, t2);
          t5 = Fp.sub(t5, X3);
          Z3 = Fp.mul(a, t4);
          X3 = Fp.mul(b3, t2);
          Z3 = Fp.add(X3, Z3);
          X3 = Fp.sub(t1, Z3);
          Z3 = Fp.add(t1, Z3);
          Y3 = Fp.mul(X3, Z3);
          t1 = Fp.add(t0, t0);
          t1 = Fp.add(t1, t0);
          t2 = Fp.mul(a, t2);
          t4 = Fp.mul(b3, t4);
          t1 = Fp.add(t1, t2);
          t2 = Fp.sub(t0, t2);
          t2 = Fp.mul(a, t2);
          t4 = Fp.add(t4, t2);
          t0 = Fp.mul(t1, t4);
          Y3 = Fp.add(Y3, t0);
          t0 = Fp.mul(t5, t4);
          X3 = Fp.mul(t3, X3);
          X3 = Fp.sub(X3, t0);
          t0 = Fp.mul(t3, t1);
          Z3 = Fp.mul(t5, Z3);
          Z3 = Fp.add(Z3, t0);
          return new Point(X3, Y3, Z3);
        }
        subtract(other) {
          return this.add(other.negate());
        }
        is0() {
          return this.equals(Point.ZERO);
        }
        /**
         * Constant time multiplication.
         * Uses wNAF method. Windowed method may be 10% faster,
         * but takes 2x longer to generate and consumes 2x memory.
         * Uses precomputes when available.
         * Uses endomorphism for Koblitz curves.
         * @param scalar by which the point would be multiplied
         * @returns New point
         */
        multiply(scalar) {
          const { endo: endo2 } = extraOpts;
          if (!Fn.isValidNot0(scalar))
            throw new Error("invalid scalar: out of range");
          let point, fake;
          const mul = (n) => wnaf.cached(this, n, (p) => (0, curve_ts_1.normalizeZ)(Point, p));
          if (endo2) {
            const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
            const { p: k1p, f: k1f } = mul(k1);
            const { p: k2p, f: k2f } = mul(k2);
            fake = k1f.add(k2f);
            point = finishEndo(endo2.beta, k1p, k2p, k1neg, k2neg);
          } else {
            const { p, f } = mul(scalar);
            point = p;
            fake = f;
          }
          return (0, curve_ts_1.normalizeZ)(Point, [point, fake])[0];
        }
        /**
         * Non-constant-time multiplication. Uses double-and-add algorithm.
         * It's faster, but should only be used when you don't care about
         * an exposed secret key e.g. sig verification, which works over *public* keys.
         */
        multiplyUnsafe(sc) {
          const { endo: endo2 } = extraOpts;
          const p = this;
          if (!Fn.isValid(sc))
            throw new Error("invalid scalar: out of range");
          if (sc === _0n || p.is0())
            return Point.ZERO;
          if (sc === _1n)
            return p;
          if (wnaf.hasCache(this))
            return this.multiply(sc);
          if (endo2) {
            const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
            const { p1, p2 } = (0, curve_ts_1.mulEndoUnsafe)(Point, p, k1, k2);
            return finishEndo(endo2.beta, p1, p2, k1neg, k2neg);
          } else {
            return wnaf.unsafe(p, sc);
          }
        }
        multiplyAndAddUnsafe(Q, a, b) {
          const sum = this.multiplyUnsafe(a).add(Q.multiplyUnsafe(b));
          return sum.is0() ? void 0 : sum;
        }
        /**
         * Converts Projective point to affine (x, y) coordinates.
         * @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
         */
        toAffine(invertedZ) {
          return toAffineMemo(this, invertedZ);
        }
        /**
         * Checks whether Point is free of torsion elements (is in prime subgroup).
         * Always torsion-free for cofactor=1 curves.
         */
        isTorsionFree() {
          const { isTorsionFree } = extraOpts;
          if (cofactor === _1n)
            return true;
          if (isTorsionFree)
            return isTorsionFree(Point, this);
          return wnaf.unsafe(this, CURVE_ORDER).is0();
        }
        clearCofactor() {
          const { clearCofactor } = extraOpts;
          if (cofactor === _1n)
            return this;
          if (clearCofactor)
            return clearCofactor(Point, this);
          return this.multiplyUnsafe(cofactor);
        }
        isSmallOrder() {
          return this.multiplyUnsafe(cofactor).is0();
        }
        toBytes(isCompressed = true) {
          (0, utils_ts_1._abool2)(isCompressed, "isCompressed");
          this.assertValidity();
          return encodePoint(Point, this, isCompressed);
        }
        toHex(isCompressed = true) {
          return (0, utils_ts_1.bytesToHex)(this.toBytes(isCompressed));
        }
        toString() {
          return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
        }
        // TODO: remove
        get px() {
          return this.X;
        }
        get py() {
          return this.X;
        }
        get pz() {
          return this.Z;
        }
        toRawBytes(isCompressed = true) {
          return this.toBytes(isCompressed);
        }
        _setWindowSize(windowSize) {
          this.precompute(windowSize);
        }
        static normalizeZ(points) {
          return (0, curve_ts_1.normalizeZ)(Point, points);
        }
        static msm(points, scalars) {
          return (0, curve_ts_1.pippenger)(Point, Fn, points, scalars);
        }
        static fromPrivateKey(privateKey) {
          return Point.BASE.multiply(_normFnElement(Fn, privateKey));
        }
      }
      Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
      Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
      Point.Fp = Fp;
      Point.Fn = Fn;
      const bits = Fn.BITS;
      const wnaf = new curve_ts_1.wNAF(Point, extraOpts.endo ? Math.ceil(bits / 2) : bits);
      Point.BASE.precompute(8);
      return Point;
    }
    function pprefix(hasEvenY) {
      return Uint8Array.of(hasEvenY ? 2 : 3);
    }
    function SWUFpSqrtRatio(Fp, Z) {
      const q = Fp.ORDER;
      let l = _0n;
      for (let o = q - _1n; o % _2n === _0n; o /= _2n)
        l += _1n;
      const c1 = l;
      const _2n_pow_c1_1 = _2n << c1 - _1n - _1n;
      const _2n_pow_c1 = _2n_pow_c1_1 * _2n;
      const c2 = (q - _1n) / _2n_pow_c1;
      const c3 = (c2 - _1n) / _2n;
      const c4 = _2n_pow_c1 - _1n;
      const c5 = _2n_pow_c1_1;
      const c6 = Fp.pow(Z, c2);
      const c7 = Fp.pow(Z, (c2 + _1n) / _2n);
      let sqrtRatio = (u, v) => {
        let tv1 = c6;
        let tv2 = Fp.pow(v, c4);
        let tv3 = Fp.sqr(tv2);
        tv3 = Fp.mul(tv3, v);
        let tv5 = Fp.mul(u, tv3);
        tv5 = Fp.pow(tv5, c3);
        tv5 = Fp.mul(tv5, tv2);
        tv2 = Fp.mul(tv5, v);
        tv3 = Fp.mul(tv5, u);
        let tv4 = Fp.mul(tv3, tv2);
        tv5 = Fp.pow(tv4, c5);
        let isQR = Fp.eql(tv5, Fp.ONE);
        tv2 = Fp.mul(tv3, c7);
        tv5 = Fp.mul(tv4, tv1);
        tv3 = Fp.cmov(tv2, tv3, isQR);
        tv4 = Fp.cmov(tv5, tv4, isQR);
        for (let i = c1; i > _1n; i--) {
          let tv52 = i - _2n;
          tv52 = _2n << tv52 - _1n;
          let tvv5 = Fp.pow(tv4, tv52);
          const e1 = Fp.eql(tvv5, Fp.ONE);
          tv2 = Fp.mul(tv3, tv1);
          tv1 = Fp.mul(tv1, tv1);
          tvv5 = Fp.mul(tv4, tv1);
          tv3 = Fp.cmov(tv2, tv3, e1);
          tv4 = Fp.cmov(tvv5, tv4, e1);
        }
        return { isValid: isQR, value: tv3 };
      };
      if (Fp.ORDER % _4n === _3n) {
        const c12 = (Fp.ORDER - _3n) / _4n;
        const c22 = Fp.sqrt(Fp.neg(Z));
        sqrtRatio = (u, v) => {
          let tv1 = Fp.sqr(v);
          const tv2 = Fp.mul(u, v);
          tv1 = Fp.mul(tv1, tv2);
          let y1 = Fp.pow(tv1, c12);
          y1 = Fp.mul(y1, tv2);
          const y2 = Fp.mul(y1, c22);
          const tv3 = Fp.mul(Fp.sqr(y1), v);
          const isQR = Fp.eql(tv3, u);
          let y = Fp.cmov(y2, y1, isQR);
          return { isValid: isQR, value: y };
        };
      }
      return sqrtRatio;
    }
    function mapToCurveSimpleSWU(Fp, opts) {
      (0, modular_ts_1.validateField)(Fp);
      const { A, B, Z } = opts;
      if (!Fp.isValid(A) || !Fp.isValid(B) || !Fp.isValid(Z))
        throw new Error("mapToCurveSimpleSWU: invalid opts");
      const sqrtRatio = SWUFpSqrtRatio(Fp, Z);
      if (!Fp.isOdd)
        throw new Error("Field does not have .isOdd()");
      return (u) => {
        let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
        tv1 = Fp.sqr(u);
        tv1 = Fp.mul(tv1, Z);
        tv2 = Fp.sqr(tv1);
        tv2 = Fp.add(tv2, tv1);
        tv3 = Fp.add(tv2, Fp.ONE);
        tv3 = Fp.mul(tv3, B);
        tv4 = Fp.cmov(Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO));
        tv4 = Fp.mul(tv4, A);
        tv2 = Fp.sqr(tv3);
        tv6 = Fp.sqr(tv4);
        tv5 = Fp.mul(tv6, A);
        tv2 = Fp.add(tv2, tv5);
        tv2 = Fp.mul(tv2, tv3);
        tv6 = Fp.mul(tv6, tv4);
        tv5 = Fp.mul(tv6, B);
        tv2 = Fp.add(tv2, tv5);
        x = Fp.mul(tv1, tv3);
        const { isValid, value } = sqrtRatio(tv2, tv6);
        y = Fp.mul(tv1, u);
        y = Fp.mul(y, value);
        x = Fp.cmov(x, tv3, isValid);
        y = Fp.cmov(y, value, isValid);
        const e1 = Fp.isOdd(u) === Fp.isOdd(y);
        y = Fp.cmov(Fp.neg(y), y, e1);
        const tv4_inv = (0, modular_ts_1.FpInvertBatch)(Fp, [tv4], true)[0];
        x = Fp.mul(x, tv4_inv);
        return { x, y };
      };
    }
    function getWLengths(Fp, Fn) {
      return {
        secretKey: Fn.BYTES,
        publicKey: 1 + Fp.BYTES,
        publicKeyUncompressed: 1 + 2 * Fp.BYTES,
        publicKeyHasPrefix: true,
        signature: 2 * Fn.BYTES
      };
    }
    function ecdh(Point, ecdhOpts = {}) {
      const { Fn } = Point;
      const randomBytes_ = ecdhOpts.randomBytes || utils_ts_1.randomBytes;
      const lengths = Object.assign(getWLengths(Point.Fp, Fn), { seed: (0, modular_ts_1.getMinHashLength)(Fn.ORDER) });
      function isValidSecretKey(secretKey) {
        try {
          return !!_normFnElement(Fn, secretKey);
        } catch (error) {
          return false;
        }
      }
      function isValidPublicKey(publicKey, isCompressed) {
        const { publicKey: comp, publicKeyUncompressed } = lengths;
        try {
          const l = publicKey.length;
          if (isCompressed === true && l !== comp)
            return false;
          if (isCompressed === false && l !== publicKeyUncompressed)
            return false;
          return !!Point.fromBytes(publicKey);
        } catch (error) {
          return false;
        }
      }
      function randomSecretKey(seed = randomBytes_(lengths.seed)) {
        return (0, modular_ts_1.mapHashToField)((0, utils_ts_1._abytes2)(seed, lengths.seed, "seed"), Fn.ORDER);
      }
      function getPublicKey(secretKey, isCompressed = true) {
        return Point.BASE.multiply(_normFnElement(Fn, secretKey)).toBytes(isCompressed);
      }
      function keygen(seed) {
        const secretKey = randomSecretKey(seed);
        return { secretKey, publicKey: getPublicKey(secretKey) };
      }
      function isProbPub(item) {
        if (typeof item === "bigint")
          return false;
        if (item instanceof Point)
          return true;
        const { secretKey, publicKey, publicKeyUncompressed } = lengths;
        if (Fn.allowedLengths || secretKey === publicKey)
          return void 0;
        const l = (0, utils_ts_1.ensureBytes)("key", item).length;
        return l === publicKey || l === publicKeyUncompressed;
      }
      function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
        if (isProbPub(secretKeyA) === true)
          throw new Error("first arg must be private key");
        if (isProbPub(publicKeyB) === false)
          throw new Error("second arg must be public key");
        const s = _normFnElement(Fn, secretKeyA);
        const b = Point.fromHex(publicKeyB);
        return b.multiply(s).toBytes(isCompressed);
      }
      const utils = {
        isValidSecretKey,
        isValidPublicKey,
        randomSecretKey,
        // TODO: remove
        isValidPrivateKey: isValidSecretKey,
        randomPrivateKey: randomSecretKey,
        normPrivateKeyToScalar: (key) => _normFnElement(Fn, key),
        precompute(windowSize = 8, point = Point.BASE) {
          return point.precompute(windowSize, false);
        }
      };
      return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
    }
    function ecdsa(Point, hash2, ecdsaOpts = {}) {
      (0, utils_1.ahash)(hash2);
      (0, utils_ts_1._validateObject)(ecdsaOpts, {}, {
        hmac: "function",
        lowS: "boolean",
        randomBytes: "function",
        bits2int: "function",
        bits2int_modN: "function"
      });
      const randomBytes2 = ecdsaOpts.randomBytes || utils_ts_1.randomBytes;
      const hmac = ecdsaOpts.hmac || ((key, ...msgs) => (0, hmac_js_1.hmac)(hash2, key, (0, utils_ts_1.concatBytes)(...msgs)));
      const { Fp, Fn } = Point;
      const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
      const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, ecdsaOpts);
      const defaultSigOpts = {
        prehash: false,
        lowS: typeof ecdsaOpts.lowS === "boolean" ? ecdsaOpts.lowS : false,
        format: void 0,
        //'compact' as ECDSASigFormat,
        extraEntropy: false
      };
      const defaultSigOpts_format = "compact";
      function isBiggerThanHalfOrder(number) {
        const HALF = CURVE_ORDER >> _1n;
        return number > HALF;
      }
      function validateRS(title, num) {
        if (!Fn.isValidNot0(num))
          throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
        return num;
      }
      function validateSigLength(bytes, format) {
        validateSigFormat(format);
        const size = lengths.signature;
        const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
        return (0, utils_ts_1._abytes2)(bytes, sizer, `${format} signature`);
      }
      class Signature {
        constructor(r, s, recovery) {
          this.r = validateRS("r", r);
          this.s = validateRS("s", s);
          if (recovery != null)
            this.recovery = recovery;
          Object.freeze(this);
        }
        static fromBytes(bytes, format = defaultSigOpts_format) {
          validateSigLength(bytes, format);
          let recid;
          if (format === "der") {
            const { r: r2, s: s2 } = exports$1.DER.toSig((0, utils_ts_1._abytes2)(bytes));
            return new Signature(r2, s2);
          }
          if (format === "recovered") {
            recid = bytes[0];
            format = "compact";
            bytes = bytes.subarray(1);
          }
          const L = Fn.BYTES;
          const r = bytes.subarray(0, L);
          const s = bytes.subarray(L, L * 2);
          return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
        }
        static fromHex(hex, format) {
          return this.fromBytes((0, utils_ts_1.hexToBytes)(hex), format);
        }
        addRecoveryBit(recovery) {
          return new Signature(this.r, this.s, recovery);
        }
        recoverPublicKey(messageHash) {
          const FIELD_ORDER = Fp.ORDER;
          const { r, s, recovery: rec } = this;
          if (rec == null || ![0, 1, 2, 3].includes(rec))
            throw new Error("recovery id invalid");
          const hasCofactor = CURVE_ORDER * _2n < FIELD_ORDER;
          if (hasCofactor && rec > 1)
            throw new Error("recovery id is ambiguous for h>1 curve");
          const radj = rec === 2 || rec === 3 ? r + CURVE_ORDER : r;
          if (!Fp.isValid(radj))
            throw new Error("recovery id 2 or 3 invalid");
          const x = Fp.toBytes(radj);
          const R = Point.fromBytes((0, utils_ts_1.concatBytes)(pprefix((rec & 1) === 0), x));
          const ir = Fn.inv(radj);
          const h = bits2int_modN((0, utils_ts_1.ensureBytes)("msgHash", messageHash));
          const u1 = Fn.create(-h * ir);
          const u2 = Fn.create(s * ir);
          const Q = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
          if (Q.is0())
            throw new Error("point at infinify");
          Q.assertValidity();
          return Q;
        }
        // Signatures should be low-s, to prevent malleability.
        hasHighS() {
          return isBiggerThanHalfOrder(this.s);
        }
        toBytes(format = defaultSigOpts_format) {
          validateSigFormat(format);
          if (format === "der")
            return (0, utils_ts_1.hexToBytes)(exports$1.DER.hexFromSig(this));
          const r = Fn.toBytes(this.r);
          const s = Fn.toBytes(this.s);
          if (format === "recovered") {
            if (this.recovery == null)
              throw new Error("recovery bit must be present");
            return (0, utils_ts_1.concatBytes)(Uint8Array.of(this.recovery), r, s);
          }
          return (0, utils_ts_1.concatBytes)(r, s);
        }
        toHex(format) {
          return (0, utils_ts_1.bytesToHex)(this.toBytes(format));
        }
        // TODO: remove
        assertValidity() {
        }
        static fromCompact(hex) {
          return Signature.fromBytes((0, utils_ts_1.ensureBytes)("sig", hex), "compact");
        }
        static fromDER(hex) {
          return Signature.fromBytes((0, utils_ts_1.ensureBytes)("sig", hex), "der");
        }
        normalizeS() {
          return this.hasHighS() ? new Signature(this.r, Fn.neg(this.s), this.recovery) : this;
        }
        toDERRawBytes() {
          return this.toBytes("der");
        }
        toDERHex() {
          return (0, utils_ts_1.bytesToHex)(this.toBytes("der"));
        }
        toCompactRawBytes() {
          return this.toBytes("compact");
        }
        toCompactHex() {
          return (0, utils_ts_1.bytesToHex)(this.toBytes("compact"));
        }
      }
      const bits2int = ecdsaOpts.bits2int || function bits2int_def(bytes) {
        if (bytes.length > 8192)
          throw new Error("input is too large");
        const num = (0, utils_ts_1.bytesToNumberBE)(bytes);
        const delta = bytes.length * 8 - fnBits;
        return delta > 0 ? num >> BigInt(delta) : num;
      };
      const bits2int_modN = ecdsaOpts.bits2int_modN || function bits2int_modN_def(bytes) {
        return Fn.create(bits2int(bytes));
      };
      const ORDER_MASK = (0, utils_ts_1.bitMask)(fnBits);
      function int2octets(num) {
        (0, utils_ts_1.aInRange)("num < 2^" + fnBits, num, _0n, ORDER_MASK);
        return Fn.toBytes(num);
      }
      function validateMsgAndHash(message, prehash) {
        (0, utils_ts_1._abytes2)(message, void 0, "message");
        return prehash ? (0, utils_ts_1._abytes2)(hash2(message), void 0, "prehashed message") : message;
      }
      function prepSig(message, privateKey, opts) {
        if (["recovered", "canonical"].some((k) => k in opts))
          throw new Error("sign() legacy options not supported");
        const { lowS, prehash, extraEntropy } = validateSigOpts(opts, defaultSigOpts);
        message = validateMsgAndHash(message, prehash);
        const h1int = bits2int_modN(message);
        const d = _normFnElement(Fn, privateKey);
        const seedArgs = [int2octets(d), int2octets(h1int)];
        if (extraEntropy != null && extraEntropy !== false) {
          const e = extraEntropy === true ? randomBytes2(lengths.secretKey) : extraEntropy;
          seedArgs.push((0, utils_ts_1.ensureBytes)("extraEntropy", e));
        }
        const seed = (0, utils_ts_1.concatBytes)(...seedArgs);
        const m = h1int;
        function k2sig(kBytes) {
          const k = bits2int(kBytes);
          if (!Fn.isValidNot0(k))
            return;
          const ik = Fn.inv(k);
          const q = Point.BASE.multiply(k).toAffine();
          const r = Fn.create(q.x);
          if (r === _0n)
            return;
          const s = Fn.create(ik * Fn.create(m + r * d));
          if (s === _0n)
            return;
          let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n);
          let normS = s;
          if (lowS && isBiggerThanHalfOrder(s)) {
            normS = Fn.neg(s);
            recovery ^= 1;
          }
          return new Signature(r, normS, recovery);
        }
        return { seed, k2sig };
      }
      function sign(message, secretKey, opts = {}) {
        message = (0, utils_ts_1.ensureBytes)("message", message);
        const { seed, k2sig } = prepSig(message, secretKey, opts);
        const drbg = (0, utils_ts_1.createHmacDrbg)(hash2.outputLen, Fn.BYTES, hmac);
        const sig = drbg(seed, k2sig);
        return sig;
      }
      function tryParsingSig(sg) {
        let sig = void 0;
        const isHex = typeof sg === "string" || (0, utils_ts_1.isBytes)(sg);
        const isObj = !isHex && sg !== null && typeof sg === "object" && typeof sg.r === "bigint" && typeof sg.s === "bigint";
        if (!isHex && !isObj)
          throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
        if (isObj) {
          sig = new Signature(sg.r, sg.s);
        } else if (isHex) {
          try {
            sig = Signature.fromBytes((0, utils_ts_1.ensureBytes)("sig", sg), "der");
          } catch (derError) {
            if (!(derError instanceof exports$1.DER.Err))
              throw derError;
          }
          if (!sig) {
            try {
              sig = Signature.fromBytes((0, utils_ts_1.ensureBytes)("sig", sg), "compact");
            } catch (error) {
              return false;
            }
          }
        }
        if (!sig)
          return false;
        return sig;
      }
      function verify2(signature, message, publicKey, opts = {}) {
        const { lowS, prehash, format } = validateSigOpts(opts, defaultSigOpts);
        publicKey = (0, utils_ts_1.ensureBytes)("publicKey", publicKey);
        message = validateMsgAndHash((0, utils_ts_1.ensureBytes)("message", message), prehash);
        if ("strict" in opts)
          throw new Error("options.strict was renamed to lowS");
        const sig = format === void 0 ? tryParsingSig(signature) : Signature.fromBytes((0, utils_ts_1.ensureBytes)("sig", signature), format);
        if (sig === false)
          return false;
        try {
          const P = Point.fromBytes(publicKey);
          if (lowS && sig.hasHighS())
            return false;
          const { r, s } = sig;
          const h = bits2int_modN(message);
          const is = Fn.inv(s);
          const u1 = Fn.create(h * is);
          const u2 = Fn.create(r * is);
          const R = Point.BASE.multiplyUnsafe(u1).add(P.multiplyUnsafe(u2));
          if (R.is0())
            return false;
          const v = Fn.create(R.x);
          return v === r;
        } catch (e) {
          return false;
        }
      }
      function recoverPublicKey(signature, message, opts = {}) {
        const { prehash } = validateSigOpts(opts, defaultSigOpts);
        message = validateMsgAndHash(message, prehash);
        return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
      }
      return Object.freeze({
        keygen,
        getPublicKey,
        getSharedSecret,
        utils,
        lengths,
        Point,
        sign,
        verify: verify2,
        recoverPublicKey,
        Signature,
        hash: hash2
      });
    }
    function weierstrassPoints(c) {
      const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
      const Point = weierstrassN(CURVE, curveOpts);
      return _weierstrass_new_output_to_legacy(c, Point);
    }
    function _weierstrass_legacy_opts_to_new(c) {
      const CURVE = {
        a: c.a,
        b: c.b,
        p: c.Fp.ORDER,
        n: c.n,
        h: c.h,
        Gx: c.Gx,
        Gy: c.Gy
      };
      const Fp = c.Fp;
      let allowedLengths = c.allowedPrivateKeyLengths ? Array.from(new Set(c.allowedPrivateKeyLengths.map((l) => Math.ceil(l / 2)))) : void 0;
      const Fn = (0, modular_ts_1.Field)(CURVE.n, {
        BITS: c.nBitLength,
        allowedLengths,
        modFromBytes: c.wrapPrivateKey
      });
      const curveOpts = {
        Fp,
        Fn,
        allowInfinityPoint: c.allowInfinityPoint,
        endo: c.endo,
        isTorsionFree: c.isTorsionFree,
        clearCofactor: c.clearCofactor,
        fromBytes: c.fromBytes,
        toBytes: c.toBytes
      };
      return { CURVE, curveOpts };
    }
    function _ecdsa_legacy_opts_to_new(c) {
      const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
      const ecdsaOpts = {
        hmac: c.hmac,
        randomBytes: c.randomBytes,
        lowS: c.lowS,
        bits2int: c.bits2int,
        bits2int_modN: c.bits2int_modN
      };
      return { CURVE, curveOpts, hash: c.hash, ecdsaOpts };
    }
    function _legacyHelperEquat(Fp, a, b) {
      function weierstrassEquation(x) {
        const x2 = Fp.sqr(x);
        const x3 = Fp.mul(x2, x);
        return Fp.add(Fp.add(x3, Fp.mul(x, a)), b);
      }
      return weierstrassEquation;
    }
    function _weierstrass_new_output_to_legacy(c, Point) {
      const { Fp, Fn } = Point;
      function isWithinCurveOrder(num) {
        return (0, utils_ts_1.inRange)(num, _1n, Fn.ORDER);
      }
      const weierstrassEquation = _legacyHelperEquat(Fp, c.a, c.b);
      return Object.assign({}, {
        CURVE: c,
        Point,
        ProjectivePoint: Point,
        normPrivateKeyToScalar: (key) => _normFnElement(Fn, key),
        weierstrassEquation,
        isWithinCurveOrder
      });
    }
    function _ecdsa_new_output_to_legacy(c, _ecdsa) {
      const Point = _ecdsa.Point;
      return Object.assign({}, _ecdsa, {
        ProjectivePoint: Point,
        CURVE: Object.assign({}, c, (0, modular_ts_1.nLength)(Point.Fn.ORDER, Point.Fn.BITS))
      });
    }
    function weierstrass(c) {
      const { CURVE, curveOpts, hash: hash2, ecdsaOpts } = _ecdsa_legacy_opts_to_new(c);
      const Point = weierstrassN(CURVE, curveOpts);
      const signs = ecdsa(Point, hash2, ecdsaOpts);
      return _ecdsa_new_output_to_legacy(c, signs);
    }
  }
});

// node_modules/@noble/curves/_shortw_utils.js
var require_shortw_utils = __commonJS({
  "node_modules/@noble/curves/_shortw_utils.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.getHash = getHash;
    exports$1.createCurve = createCurve;
    var weierstrass_ts_1 = require_weierstrass();
    function getHash(hash2) {
      return { hash: hash2 };
    }
    function createCurve(curveDef, defHash) {
      const create = (hash2) => (0, weierstrass_ts_1.weierstrass)({ ...curveDef, hash: hash2 });
      return { ...create(defHash), create };
    }
  }
});

// node_modules/@noble/curves/abstract/hash-to-curve.js
var require_hash_to_curve = __commonJS({
  "node_modules/@noble/curves/abstract/hash-to-curve.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1._DST_scalar = void 0;
    exports$1.expand_message_xmd = expand_message_xmd;
    exports$1.expand_message_xof = expand_message_xof;
    exports$1.hash_to_field = hash_to_field;
    exports$1.isogenyMap = isogenyMap;
    exports$1.createHasher = createHasher;
    var utils_ts_1 = require_utils4();
    var modular_ts_1 = require_modular();
    var os2ip = utils_ts_1.bytesToNumberBE;
    function i2osp(value, length) {
      anum(value);
      anum(length);
      if (value < 0 || value >= 1 << 8 * length)
        throw new Error("invalid I2OSP input: " + value);
      const res = Array.from({ length }).fill(0);
      for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 255;
        value >>>= 8;
      }
      return new Uint8Array(res);
    }
    function strxor(a, b) {
      const arr = new Uint8Array(a.length);
      for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
      }
      return arr;
    }
    function anum(item) {
      if (!Number.isSafeInteger(item))
        throw new Error("number expected");
    }
    function normDST(DST) {
      if (!(0, utils_ts_1.isBytes)(DST) && typeof DST !== "string")
        throw new Error("DST must be Uint8Array or string");
      return typeof DST === "string" ? (0, utils_ts_1.utf8ToBytes)(DST) : DST;
    }
    function expand_message_xmd(msg, DST, lenInBytes, H) {
      (0, utils_ts_1.abytes)(msg);
      anum(lenInBytes);
      DST = normDST(DST);
      if (DST.length > 255)
        DST = H((0, utils_ts_1.concatBytes)((0, utils_ts_1.utf8ToBytes)("H2C-OVERSIZE-DST-"), DST));
      const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
      const ell = Math.ceil(lenInBytes / b_in_bytes);
      if (lenInBytes > 65535 || ell > 255)
        throw new Error("expand_message_xmd: invalid lenInBytes");
      const DST_prime = (0, utils_ts_1.concatBytes)(DST, i2osp(DST.length, 1));
      const Z_pad = i2osp(0, r_in_bytes);
      const l_i_b_str = i2osp(lenInBytes, 2);
      const b = new Array(ell);
      const b_0 = H((0, utils_ts_1.concatBytes)(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
      b[0] = H((0, utils_ts_1.concatBytes)(b_0, i2osp(1, 1), DST_prime));
      for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = H((0, utils_ts_1.concatBytes)(...args));
      }
      const pseudo_random_bytes = (0, utils_ts_1.concatBytes)(...b);
      return pseudo_random_bytes.slice(0, lenInBytes);
    }
    function expand_message_xof(msg, DST, lenInBytes, k, H) {
      (0, utils_ts_1.abytes)(msg);
      anum(lenInBytes);
      DST = normDST(DST);
      if (DST.length > 255) {
        const dkLen = Math.ceil(2 * k / 8);
        DST = H.create({ dkLen }).update((0, utils_ts_1.utf8ToBytes)("H2C-OVERSIZE-DST-")).update(DST).digest();
      }
      if (lenInBytes > 65535 || DST.length > 255)
        throw new Error("expand_message_xof: invalid lenInBytes");
      return H.create({ dkLen: lenInBytes }).update(msg).update(i2osp(lenInBytes, 2)).update(DST).update(i2osp(DST.length, 1)).digest();
    }
    function hash_to_field(msg, count, options) {
      (0, utils_ts_1._validateObject)(options, {
        p: "bigint",
        m: "number",
        k: "number",
        hash: "function"
      });
      const { p, k, m, hash: hash2, expand, DST } = options;
      if (!(0, utils_ts_1.isHash)(options.hash))
        throw new Error("expected valid hash");
      (0, utils_ts_1.abytes)(msg);
      anum(count);
      const log2p = p.toString(2).length;
      const L = Math.ceil((log2p + k) / 8);
      const len_in_bytes = count * m * L;
      let prb;
      if (expand === "xmd") {
        prb = expand_message_xmd(msg, DST, len_in_bytes, hash2);
      } else if (expand === "xof") {
        prb = expand_message_xof(msg, DST, len_in_bytes, k, hash2);
      } else if (expand === "_internal_pass") {
        prb = msg;
      } else {
        throw new Error('expand must be "xmd" or "xof"');
      }
      const u = new Array(count);
      for (let i = 0; i < count; i++) {
        const e = new Array(m);
        for (let j = 0; j < m; j++) {
          const elm_offset = L * (j + i * m);
          const tv = prb.subarray(elm_offset, elm_offset + L);
          e[j] = (0, modular_ts_1.mod)(os2ip(tv), p);
        }
        u[i] = e;
      }
      return u;
    }
    function isogenyMap(field, map) {
      const coeff = map.map((i) => Array.from(i).reverse());
      return (x, y) => {
        const [xn, xd, yn, yd] = coeff.map((val) => val.reduce((acc, i) => field.add(field.mul(acc, x), i)));
        const [xd_inv, yd_inv] = (0, modular_ts_1.FpInvertBatch)(field, [xd, yd], true);
        x = field.mul(xn, xd_inv);
        y = field.mul(y, field.mul(yn, yd_inv));
        return { x, y };
      };
    }
    exports$1._DST_scalar = (0, utils_ts_1.utf8ToBytes)("HashToScalar-");
    function createHasher(Point, mapToCurve, defaults) {
      if (typeof mapToCurve !== "function")
        throw new Error("mapToCurve() must be defined");
      function map(num) {
        return Point.fromAffine(mapToCurve(num));
      }
      function clear(initial) {
        const P = initial.clearCofactor();
        if (P.equals(Point.ZERO))
          return Point.ZERO;
        P.assertValidity();
        return P;
      }
      return {
        defaults,
        hashToCurve(msg, options) {
          const opts = Object.assign({}, defaults, options);
          const u = hash_to_field(msg, 2, opts);
          const u0 = map(u[0]);
          const u1 = map(u[1]);
          return clear(u0.add(u1));
        },
        encodeToCurve(msg, options) {
          const optsDst = defaults.encodeDST ? { DST: defaults.encodeDST } : {};
          const opts = Object.assign({}, defaults, optsDst, options);
          const u = hash_to_field(msg, 1, opts);
          const u0 = map(u[0]);
          return clear(u0);
        },
        /** See {@link H2CHasher} */
        mapToCurve(scalars) {
          if (!Array.isArray(scalars))
            throw new Error("expected array of bigints");
          for (const i of scalars)
            if (typeof i !== "bigint")
              throw new Error("expected array of bigints");
          return clear(map(scalars));
        },
        // hash_to_scalar can produce 0: https://www.rfc-editor.org/errata/eid8393
        // RFC 9380, draft-irtf-cfrg-bbs-signatures-08
        hashToScalar(msg, options) {
          const N = Point.Fn.ORDER;
          const opts = Object.assign({}, defaults, { p: N, m: 1, DST: exports$1._DST_scalar }, options);
          return hash_to_field(msg, 1, opts)[0][0];
        }
      };
    }
  }
});

// node_modules/@noble/curves/secp256k1.js
var require_secp256k1 = __commonJS({
  "node_modules/@noble/curves/secp256k1.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.encodeToCurve = exports$1.hashToCurve = exports$1.secp256k1_hasher = exports$1.schnorr = exports$1.secp256k1 = void 0;
    var sha2_js_1 = require_sha2();
    var utils_js_1 = require_utils();
    var _shortw_utils_ts_1 = require_shortw_utils();
    var hash_to_curve_ts_1 = require_hash_to_curve();
    var modular_ts_1 = require_modular();
    var weierstrass_ts_1 = require_weierstrass();
    var utils_ts_1 = require_utils4();
    var secp256k1_CURVE = {
      p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
      n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
      h: BigInt(1),
      a: BigInt(0),
      b: BigInt(7),
      Gx: BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
      Gy: BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    };
    var secp256k1_ENDO = {
      beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
      basises: [
        [BigInt("0x3086d221a7d46bcde86c90e49284eb15"), -BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],
        [BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), BigInt("0x3086d221a7d46bcde86c90e49284eb15")]
      ]
    };
    var _0n = /* @__PURE__ */ BigInt(0);
    var _1n = /* @__PURE__ */ BigInt(1);
    var _2n = /* @__PURE__ */ BigInt(2);
    function sqrtMod(y) {
      const P = secp256k1_CURVE.p;
      const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
      const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
      const b2 = y * y * y % P;
      const b3 = b2 * b2 * y % P;
      const b6 = (0, modular_ts_1.pow2)(b3, _3n, P) * b3 % P;
      const b9 = (0, modular_ts_1.pow2)(b6, _3n, P) * b3 % P;
      const b11 = (0, modular_ts_1.pow2)(b9, _2n, P) * b2 % P;
      const b22 = (0, modular_ts_1.pow2)(b11, _11n, P) * b11 % P;
      const b44 = (0, modular_ts_1.pow2)(b22, _22n, P) * b22 % P;
      const b88 = (0, modular_ts_1.pow2)(b44, _44n, P) * b44 % P;
      const b176 = (0, modular_ts_1.pow2)(b88, _88n, P) * b88 % P;
      const b220 = (0, modular_ts_1.pow2)(b176, _44n, P) * b44 % P;
      const b223 = (0, modular_ts_1.pow2)(b220, _3n, P) * b3 % P;
      const t1 = (0, modular_ts_1.pow2)(b223, _23n, P) * b22 % P;
      const t2 = (0, modular_ts_1.pow2)(t1, _6n, P) * b2 % P;
      const root = (0, modular_ts_1.pow2)(t2, _2n, P);
      if (!Fpk1.eql(Fpk1.sqr(root), y))
        throw new Error("Cannot find square root");
      return root;
    }
    var Fpk1 = (0, modular_ts_1.Field)(secp256k1_CURVE.p, { sqrt: sqrtMod });
    exports$1.secp256k1 = (0, _shortw_utils_ts_1.createCurve)({ ...secp256k1_CURVE, Fp: Fpk1, lowS: true, endo: secp256k1_ENDO }, sha2_js_1.sha256);
    var TAGGED_HASH_PREFIXES = {};
    function taggedHash(tag, ...messages) {
      let tagP = TAGGED_HASH_PREFIXES[tag];
      if (tagP === void 0) {
        const tagH = (0, sha2_js_1.sha256)((0, utils_ts_1.utf8ToBytes)(tag));
        tagP = (0, utils_ts_1.concatBytes)(tagH, tagH);
        TAGGED_HASH_PREFIXES[tag] = tagP;
      }
      return (0, sha2_js_1.sha256)((0, utils_ts_1.concatBytes)(tagP, ...messages));
    }
    var pointToBytes = (point) => point.toBytes(true).slice(1);
    var Pointk1 = /* @__PURE__ */ (() => exports$1.secp256k1.Point)();
    var hasEven = (y) => y % _2n === _0n;
    function schnorrGetExtPubKey(priv) {
      const { Fn, BASE } = Pointk1;
      const d_ = (0, weierstrass_ts_1._normFnElement)(Fn, priv);
      const p = BASE.multiply(d_);
      const scalar = hasEven(p.y) ? d_ : Fn.neg(d_);
      return { scalar, bytes: pointToBytes(p) };
    }
    function lift_x(x) {
      const Fp = Fpk1;
      if (!Fp.isValidNot0(x))
        throw new Error("invalid x: Fail if x \u2265 p");
      const xx = Fp.create(x * x);
      const c = Fp.create(xx * x + BigInt(7));
      let y = Fp.sqrt(c);
      if (!hasEven(y))
        y = Fp.neg(y);
      const p = Pointk1.fromAffine({ x, y });
      p.assertValidity();
      return p;
    }
    var num = utils_ts_1.bytesToNumberBE;
    function challenge(...args) {
      return Pointk1.Fn.create(num(taggedHash("BIP0340/challenge", ...args)));
    }
    function schnorrGetPublicKey(secretKey) {
      return schnorrGetExtPubKey(secretKey).bytes;
    }
    function schnorrSign(message, secretKey, auxRand = (0, utils_js_1.randomBytes)(32)) {
      const { Fn } = Pointk1;
      const m = (0, utils_ts_1.ensureBytes)("message", message);
      const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey);
      const a = (0, utils_ts_1.ensureBytes)("auxRand", auxRand, 32);
      const t = Fn.toBytes(d ^ num(taggedHash("BIP0340/aux", a)));
      const rand = taggedHash("BIP0340/nonce", t, px, m);
      const { bytes: rx, scalar: k } = schnorrGetExtPubKey(rand);
      const e = challenge(rx, px, m);
      const sig = new Uint8Array(64);
      sig.set(rx, 0);
      sig.set(Fn.toBytes(Fn.create(k + e * d)), 32);
      if (!schnorrVerify(sig, m, px))
        throw new Error("sign: Invalid signature produced");
      return sig;
    }
    function schnorrVerify(signature, message, publicKey) {
      const { Fn, BASE } = Pointk1;
      const sig = (0, utils_ts_1.ensureBytes)("signature", signature, 64);
      const m = (0, utils_ts_1.ensureBytes)("message", message);
      const pub = (0, utils_ts_1.ensureBytes)("publicKey", publicKey, 32);
      try {
        const P = lift_x(num(pub));
        const r = num(sig.subarray(0, 32));
        if (!(0, utils_ts_1.inRange)(r, _1n, secp256k1_CURVE.p))
          return false;
        const s = num(sig.subarray(32, 64));
        if (!(0, utils_ts_1.inRange)(s, _1n, secp256k1_CURVE.n))
          return false;
        const e = challenge(Fn.toBytes(r), pointToBytes(P), m);
        const R = BASE.multiplyUnsafe(s).add(P.multiplyUnsafe(Fn.neg(e)));
        const { x, y } = R.toAffine();
        if (R.is0() || !hasEven(y) || x !== r)
          return false;
        return true;
      } catch (error) {
        return false;
      }
    }
    exports$1.schnorr = (() => {
      const size = 32;
      const seedLength = 48;
      const randomSecretKey = (seed = (0, utils_js_1.randomBytes)(seedLength)) => {
        return (0, modular_ts_1.mapHashToField)(seed, secp256k1_CURVE.n);
      };
      exports$1.secp256k1.utils.randomSecretKey;
      function keygen(seed) {
        const secretKey = randomSecretKey(seed);
        return { secretKey, publicKey: schnorrGetPublicKey(secretKey) };
      }
      return {
        keygen,
        getPublicKey: schnorrGetPublicKey,
        sign: schnorrSign,
        verify: schnorrVerify,
        Point: Pointk1,
        utils: {
          randomSecretKey,
          randomPrivateKey: randomSecretKey,
          taggedHash,
          // TODO: remove
          lift_x,
          pointToBytes,
          numberToBytesBE: utils_ts_1.numberToBytesBE,
          bytesToNumberBE: utils_ts_1.bytesToNumberBE,
          mod: modular_ts_1.mod
        },
        lengths: {
          secretKey: size,
          publicKey: size,
          publicKeyHasPrefix: false,
          signature: size * 2,
          seed: seedLength
        }
      };
    })();
    var isoMap = /* @__PURE__ */ (() => (0, hash_to_curve_ts_1.isogenyMap)(Fpk1, [
      // xNum
      [
        "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7",
        "0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581",
        "0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262",
        "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c"
      ],
      // xDen
      [
        "0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b",
        "0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14",
        "0x0000000000000000000000000000000000000000000000000000000000000001"
        // LAST 1
      ],
      // yNum
      [
        "0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c",
        "0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3",
        "0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931",
        "0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84"
      ],
      // yDen
      [
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b",
        "0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573",
        "0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f",
        "0x0000000000000000000000000000000000000000000000000000000000000001"
        // LAST 1
      ]
    ].map((i) => i.map((j) => BigInt(j)))))();
    var mapSWU = /* @__PURE__ */ (() => (0, weierstrass_ts_1.mapToCurveSimpleSWU)(Fpk1, {
      A: BigInt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
      B: BigInt("1771"),
      Z: Fpk1.create(BigInt("-11"))
    }))();
    exports$1.secp256k1_hasher = (() => (0, hash_to_curve_ts_1.createHasher)(exports$1.secp256k1.Point, (scalars) => {
      const { x, y } = mapSWU(Fpk1.create(scalars[0]));
      return isoMap(x, y);
    }, {
      DST: "secp256k1_XMD:SHA-256_SSWU_RO_",
      encodeDST: "secp256k1_XMD:SHA-256_SSWU_NU_",
      p: Fpk1.ORDER,
      m: 1,
      k: 128,
      expand: "xmd",
      hash: sha2_js_1.sha256
    }))();
    exports$1.hashToCurve = (() => exports$1.secp256k1_hasher.hashToCurve)();
    exports$1.encodeToCurve = (() => exports$1.secp256k1_hasher.encodeToCurve)();
  }
});

// node_modules/@xrplf/isomorphic/dist/sha512/index.js
var require_sha512 = __commonJS({
  "node_modules/@xrplf/isomorphic/dist/sha512/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.sha512 = void 0;
    var crypto_1 = __require("crypto");
    var wrapCryptoCreateHash_1 = __importDefault(require_wrapCryptoCreateHash());
    exports$1.sha512 = (0, wrapCryptoCreateHash_1.default)("sha512", crypto_1.createHash);
  }
});

// node_modules/@noble/curves/abstract/utils.js
var require_utils5 = __commonJS({
  "node_modules/@noble/curves/abstract/utils.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.isHash = exports$1.validateObject = exports$1.memoized = exports$1.notImplemented = exports$1.createHmacDrbg = exports$1.bitMask = exports$1.bitSet = exports$1.bitGet = exports$1.bitLen = exports$1.aInRange = exports$1.inRange = exports$1.asciiToBytes = exports$1.copyBytes = exports$1.equalBytes = exports$1.ensureBytes = exports$1.numberToVarBytesBE = exports$1.numberToBytesLE = exports$1.numberToBytesBE = exports$1.bytesToNumberLE = exports$1.bytesToNumberBE = exports$1.hexToNumber = exports$1.numberToHexUnpadded = exports$1.abool = exports$1.utf8ToBytes = exports$1.randomBytes = exports$1.isBytes = exports$1.hexToBytes = exports$1.concatBytes = exports$1.bytesToUtf8 = exports$1.bytesToHex = exports$1.anumber = exports$1.abytes = void 0;
    var u = require_utils4();
    exports$1.abytes = u.abytes;
    exports$1.anumber = u.anumber;
    exports$1.bytesToHex = u.bytesToHex;
    exports$1.bytesToUtf8 = u.bytesToUtf8;
    exports$1.concatBytes = u.concatBytes;
    exports$1.hexToBytes = u.hexToBytes;
    exports$1.isBytes = u.isBytes;
    exports$1.randomBytes = u.randomBytes;
    exports$1.utf8ToBytes = u.utf8ToBytes;
    exports$1.abool = u.abool;
    exports$1.numberToHexUnpadded = u.numberToHexUnpadded;
    exports$1.hexToNumber = u.hexToNumber;
    exports$1.bytesToNumberBE = u.bytesToNumberBE;
    exports$1.bytesToNumberLE = u.bytesToNumberLE;
    exports$1.numberToBytesBE = u.numberToBytesBE;
    exports$1.numberToBytesLE = u.numberToBytesLE;
    exports$1.numberToVarBytesBE = u.numberToVarBytesBE;
    exports$1.ensureBytes = u.ensureBytes;
    exports$1.equalBytes = u.equalBytes;
    exports$1.copyBytes = u.copyBytes;
    exports$1.asciiToBytes = u.asciiToBytes;
    exports$1.inRange = u.inRange;
    exports$1.aInRange = u.aInRange;
    exports$1.bitLen = u.bitLen;
    exports$1.bitGet = u.bitGet;
    exports$1.bitSet = u.bitSet;
    exports$1.bitMask = u.bitMask;
    exports$1.createHmacDrbg = u.createHmacDrbg;
    exports$1.notImplemented = u.notImplemented;
    exports$1.memoized = u.memoized;
    exports$1.validateObject = u.validateObject;
    exports$1.isHash = u.isHash;
  }
});

// node_modules/ripple-keypairs/dist/utils/Sha512.js
var require_Sha512 = __commonJS({
  "node_modules/ripple-keypairs/dist/utils/Sha512.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var sha512_1 = require_sha512();
    var utils_1 = require_utils5();
    var Sha512 = class _Sha512 {
      constructor() {
        this.hash = sha512_1.sha512.create();
      }
      static half(input) {
        return new _Sha512().add(input).first256();
      }
      add(bytes) {
        this.hash.update(bytes);
        return this;
      }
      addU32(i) {
        const buffer = new Uint8Array(4);
        new DataView(buffer.buffer).setUint32(0, i);
        return this.add(buffer);
      }
      finish() {
        return this.hash.digest();
      }
      first256() {
        return this.finish().slice(0, 32);
      }
      first256BigInt() {
        return (0, utils_1.bytesToNumberBE)(this.first256());
      }
    };
    exports$1.default = Sha512;
  }
});

// node_modules/ripple-keypairs/dist/signing-schemes/secp256k1/utils.js
var require_utils6 = __commonJS({
  "node_modules/ripple-keypairs/dist/signing-schemes/secp256k1/utils.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.accountPublicFromPublicGenerator = exports$1.derivePrivateKey = void 0;
    var secp256k1_1 = require_secp256k1();
    var Sha512_1 = __importDefault(require_Sha512());
    var ZERO = BigInt(0);
    function deriveScalar(bytes, discrim) {
      const order = secp256k1_1.secp256k1.CURVE.n;
      for (let i = 0; i <= 4294967295; i++) {
        const hasher = new Sha512_1.default().add(bytes);
        if (discrim !== void 0) {
          hasher.addU32(discrim);
        }
        hasher.addU32(i);
        const key = hasher.first256BigInt();
        if (key > ZERO && key < order) {
          return key;
        }
      }
      throw new Error("impossible unicorn ;)");
    }
    function derivePrivateKey(seed, opts = {}) {
      const root = opts.validator;
      const order = secp256k1_1.secp256k1.CURVE.n;
      const privateGen = deriveScalar(seed);
      if (root) {
        return privateGen;
      }
      const publicGen = secp256k1_1.secp256k1.ProjectivePoint.BASE.multiply(privateGen).toRawBytes(true);
      const accountIndex = opts.accountIndex || 0;
      return (deriveScalar(publicGen, accountIndex) + privateGen) % order;
    }
    exports$1.derivePrivateKey = derivePrivateKey;
    function accountPublicFromPublicGenerator(publicGenBytes) {
      const rootPubPoint = secp256k1_1.secp256k1.ProjectivePoint.fromHex(publicGenBytes);
      const scalar = deriveScalar(publicGenBytes, 0);
      const point = secp256k1_1.secp256k1.ProjectivePoint.BASE.multiply(scalar);
      const offset = rootPubPoint.add(point);
      return offset.toRawBytes(true);
    }
    exports$1.accountPublicFromPublicGenerator = accountPublicFromPublicGenerator;
  }
});

// node_modules/ripple-keypairs/dist/utils/assert.js
var require_assert = __commonJS({
  "node_modules/ripple-keypairs/dist/utils/assert.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var assertHelper = {
      ok(cond, message) {
        if (!cond) {
          throw new Error(message);
        }
      }
    };
    exports$1.default = assertHelper;
  }
});

// node_modules/ripple-keypairs/dist/utils/getAlgorithmFromKey.js
var require_getAlgorithmFromKey = __commonJS({
  "node_modules/ripple-keypairs/dist/utils/getAlgorithmFromKey.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.getAlgorithmFromPrivateKey = exports$1.getAlgorithmFromPublicKey = exports$1.getAlgorithmFromKey = void 0;
    var Prefix;
    (function(Prefix2) {
      Prefix2[Prefix2["NONE"] = -1] = "NONE";
      Prefix2[Prefix2["ED25519"] = 237] = "ED25519";
      Prefix2[Prefix2["SECP256K1_PUB_X"] = 2] = "SECP256K1_PUB_X";
      Prefix2[Prefix2["SECP256K1_PUB_X_ODD_Y"] = 3] = "SECP256K1_PUB_X_ODD_Y";
      Prefix2[Prefix2["SECP256K1_PUB_XY"] = 4] = "SECP256K1_PUB_XY";
      Prefix2[Prefix2["SECP256K1_PRIVATE"] = 0] = "SECP256K1_PRIVATE";
    })(Prefix || (Prefix = {}));
    var KEY_TYPES = {
      [`private_${Prefix.NONE}_32`]: "ecdsa-secp256k1",
      [`private_${Prefix.SECP256K1_PRIVATE}_33`]: "ecdsa-secp256k1",
      [`private_${Prefix.ED25519}_33`]: "ed25519",
      [`public_${Prefix.ED25519}_33`]: "ed25519",
      [`public_${Prefix.SECP256K1_PUB_X}_33`]: "ecdsa-secp256k1",
      [`public_${Prefix.SECP256K1_PUB_X_ODD_Y}_33`]: "ecdsa-secp256k1",
      [`public_${Prefix.SECP256K1_PUB_XY}_65`]: "ecdsa-secp256k1"
    };
    function getKeyInfo(key) {
      return {
        prefix: key.length < 2 ? Prefix.NONE : parseInt(key.slice(0, 2), 16),
        len: key.length / 2
      };
    }
    function prefixRepr(prefix) {
      return prefix === Prefix.NONE ? "None" : `0x${prefix.toString(16).padStart(2, "0")}`;
    }
    function getValidFormatsTable(type) {
      const padding = 2;
      const colWidth = {
        algorithm: "ecdsa-secp256k1".length + padding,
        prefix: "0x00".length + padding
      };
      return Object.entries(KEY_TYPES).filter(([key]) => key.startsWith(type)).map(([key, algorithm]) => {
        const [, prefix, length] = key.split("_");
        const paddedAlgo = algorithm.padEnd(colWidth.algorithm);
        const paddedPrefix = prefixRepr(Number(prefix)).padEnd(colWidth.prefix);
        return `${paddedAlgo} - Prefix: ${paddedPrefix} Length: ${length} bytes`;
      }).join("\n");
    }
    function keyError({ key, type, prefix, len }) {
      const validFormats = getValidFormatsTable(type);
      return `invalid_key:

Type: ${type}
Key: ${key}
Prefix: ${prefixRepr(prefix)} 
Length: ${len} bytes

Acceptable ${type} formats are:
${validFormats}
`;
    }
    function getAlgorithmFromKey(key, type) {
      const { prefix, len } = getKeyInfo(key);
      const usedPrefix = type === "private" && len === 32 ? Prefix.NONE : prefix;
      const algorithm = KEY_TYPES[`${type}_${usedPrefix}_${len}`];
      if (!algorithm) {
        throw new Error(keyError({ key, type, len, prefix: usedPrefix }));
      }
      return algorithm;
    }
    exports$1.getAlgorithmFromKey = getAlgorithmFromKey;
    function getAlgorithmFromPublicKey(key) {
      return getAlgorithmFromKey(key, "public");
    }
    exports$1.getAlgorithmFromPublicKey = getAlgorithmFromPublicKey;
    function getAlgorithmFromPrivateKey(key) {
      return getAlgorithmFromKey(key, "private");
    }
    exports$1.getAlgorithmFromPrivateKey = getAlgorithmFromPrivateKey;
  }
});

// node_modules/ripple-keypairs/dist/signing-schemes/secp256k1/index.js
var require_secp256k12 = __commonJS({
  "node_modules/ripple-keypairs/dist/signing-schemes/secp256k1/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var utils_1 = require_utils5();
    var secp256k1_1 = require_secp256k1();
    var utils_2 = require_utils2();
    var utils_3 = require_utils6();
    var assert_1 = __importDefault(require_assert());
    var Sha512_1 = __importDefault(require_Sha512());
    var SECP256K1_PREFIX = "00";
    var secp256k1 = {
      deriveKeypair(entropy, options) {
        const derived = (0, utils_3.derivePrivateKey)(entropy, options);
        const privateKey = SECP256K1_PREFIX + (0, utils_2.bytesToHex)((0, utils_1.numberToBytesBE)(derived, 32));
        const publicKey = (0, utils_2.bytesToHex)(secp256k1_1.secp256k1.getPublicKey(derived, true));
        return { privateKey, publicKey };
      },
      sign(message, privateKey) {
        assert_1.default.ok(privateKey.length === 66 && privateKey.startsWith(SECP256K1_PREFIX) || privateKey.length === 64);
        const normedPrivateKey = privateKey.length === 66 ? privateKey.slice(2) : privateKey;
        return secp256k1_1.secp256k1.sign(Sha512_1.default.half(message), normedPrivateKey, {
          // "Canonical" signatures
          lowS: true,
          // Would fail tests if signatures aren't deterministic
          extraEntropy: void 0
        }).toDERHex(true).toUpperCase();
      },
      verify(message, signature, publicKey) {
        const decoded = secp256k1_1.secp256k1.Signature.fromDER(signature);
        return secp256k1_1.secp256k1.verify(decoded, Sha512_1.default.half(message), publicKey);
      }
    };
    exports$1.default = secp256k1;
  }
});

// node_modules/@noble/curves/abstract/edwards.js
var require_edwards = __commonJS({
  "node_modules/@noble/curves/abstract/edwards.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.PrimeEdwardsPoint = void 0;
    exports$1.edwards = edwards;
    exports$1.eddsa = eddsa;
    exports$1.twistedEdwards = twistedEdwards;
    var utils_ts_1 = require_utils4();
    var curve_ts_1 = require_curve();
    var modular_ts_1 = require_modular();
    var _0n = BigInt(0);
    var _1n = BigInt(1);
    var _2n = BigInt(2);
    var _8n = BigInt(8);
    function isEdValidXY(Fp, CURVE, x, y) {
      const x2 = Fp.sqr(x);
      const y2 = Fp.sqr(y);
      const left = Fp.add(Fp.mul(CURVE.a, x2), y2);
      const right = Fp.add(Fp.ONE, Fp.mul(CURVE.d, Fp.mul(x2, y2)));
      return Fp.eql(left, right);
    }
    function edwards(params, extraOpts = {}) {
      const validated = (0, curve_ts_1._createCurveFields)("edwards", params, extraOpts, extraOpts.FpFnLE);
      const { Fp, Fn } = validated;
      let CURVE = validated.CURVE;
      const { h: cofactor } = CURVE;
      (0, utils_ts_1._validateObject)(extraOpts, {}, { uvRatio: "function" });
      const MASK = _2n << BigInt(Fn.BYTES * 8) - _1n;
      const modP = (n) => Fp.create(n);
      const uvRatio = extraOpts.uvRatio || ((u, v) => {
        try {
          return { isValid: true, value: Fp.sqrt(Fp.div(u, v)) };
        } catch (e) {
          return { isValid: false, value: _0n };
        }
      });
      if (!isEdValidXY(Fp, CURVE, CURVE.Gx, CURVE.Gy))
        throw new Error("bad curve params: generator point");
      function acoord(title, n, banZero = false) {
        const min = banZero ? _1n : _0n;
        (0, utils_ts_1.aInRange)("coordinate " + title, n, min, MASK);
        return n;
      }
      function aextpoint(other) {
        if (!(other instanceof Point))
          throw new Error("ExtendedPoint expected");
      }
      const toAffineMemo = (0, utils_ts_1.memoized)((p, iz) => {
        const { X, Y, Z } = p;
        const is0 = p.is0();
        if (iz == null)
          iz = is0 ? _8n : Fp.inv(Z);
        const x = modP(X * iz);
        const y = modP(Y * iz);
        const zz = Fp.mul(Z, iz);
        if (is0)
          return { x: _0n, y: _1n };
        if (zz !== _1n)
          throw new Error("invZ was invalid");
        return { x, y };
      });
      const assertValidMemo = (0, utils_ts_1.memoized)((p) => {
        const { a, d } = CURVE;
        if (p.is0())
          throw new Error("bad point: ZERO");
        const { X, Y, Z, T } = p;
        const X2 = modP(X * X);
        const Y2 = modP(Y * Y);
        const Z2 = modP(Z * Z);
        const Z4 = modP(Z2 * Z2);
        const aX2 = modP(X2 * a);
        const left = modP(Z2 * modP(aX2 + Y2));
        const right = modP(Z4 + modP(d * modP(X2 * Y2)));
        if (left !== right)
          throw new Error("bad point: equation left != right (1)");
        const XY = modP(X * Y);
        const ZT = modP(Z * T);
        if (XY !== ZT)
          throw new Error("bad point: equation left != right (2)");
        return true;
      });
      class Point {
        constructor(X, Y, Z, T) {
          this.X = acoord("x", X);
          this.Y = acoord("y", Y);
          this.Z = acoord("z", Z, true);
          this.T = acoord("t", T);
          Object.freeze(this);
        }
        static CURVE() {
          return CURVE;
        }
        static fromAffine(p) {
          if (p instanceof Point)
            throw new Error("extended point not allowed");
          const { x, y } = p || {};
          acoord("x", x);
          acoord("y", y);
          return new Point(x, y, _1n, modP(x * y));
        }
        // Uses algo from RFC8032 5.1.3.
        static fromBytes(bytes, zip215 = false) {
          const len = Fp.BYTES;
          const { a, d } = CURVE;
          bytes = (0, utils_ts_1.copyBytes)((0, utils_ts_1._abytes2)(bytes, len, "point"));
          (0, utils_ts_1._abool2)(zip215, "zip215");
          const normed = (0, utils_ts_1.copyBytes)(bytes);
          const lastByte = bytes[len - 1];
          normed[len - 1] = lastByte & -129;
          const y = (0, utils_ts_1.bytesToNumberLE)(normed);
          const max = zip215 ? MASK : Fp.ORDER;
          (0, utils_ts_1.aInRange)("point.y", y, _0n, max);
          const y2 = modP(y * y);
          const u = modP(y2 - _1n);
          const v = modP(d * y2 - a);
          let { isValid, value: x } = uvRatio(u, v);
          if (!isValid)
            throw new Error("bad point: invalid y coordinate");
          const isXOdd = (x & _1n) === _1n;
          const isLastByteOdd = (lastByte & 128) !== 0;
          if (!zip215 && x === _0n && isLastByteOdd)
            throw new Error("bad point: x=0 and x_0=1");
          if (isLastByteOdd !== isXOdd)
            x = modP(-x);
          return Point.fromAffine({ x, y });
        }
        static fromHex(bytes, zip215 = false) {
          return Point.fromBytes((0, utils_ts_1.ensureBytes)("point", bytes), zip215);
        }
        get x() {
          return this.toAffine().x;
        }
        get y() {
          return this.toAffine().y;
        }
        precompute(windowSize = 8, isLazy = true) {
          wnaf.createCache(this, windowSize);
          if (!isLazy)
            this.multiply(_2n);
          return this;
        }
        // Useful in fromAffine() - not for fromBytes(), which always created valid points.
        assertValidity() {
          assertValidMemo(this);
        }
        // Compare one point to another.
        equals(other) {
          aextpoint(other);
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const { X: X2, Y: Y2, Z: Z2 } = other;
          const X1Z2 = modP(X1 * Z2);
          const X2Z1 = modP(X2 * Z1);
          const Y1Z2 = modP(Y1 * Z2);
          const Y2Z1 = modP(Y2 * Z1);
          return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
        }
        is0() {
          return this.equals(Point.ZERO);
        }
        negate() {
          return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
        }
        // Fast algo for doubling Extended Point.
        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
        // Cost: 4M + 4S + 1*a + 6add + 1*2.
        double() {
          const { a } = CURVE;
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const A = modP(X1 * X1);
          const B = modP(Y1 * Y1);
          const C = modP(_2n * modP(Z1 * Z1));
          const D = modP(a * A);
          const x1y1 = X1 + Y1;
          const E = modP(modP(x1y1 * x1y1) - A - B);
          const G = D + B;
          const F = G - C;
          const H = D - B;
          const X3 = modP(E * F);
          const Y3 = modP(G * H);
          const T3 = modP(E * H);
          const Z3 = modP(F * G);
          return new Point(X3, Y3, Z3, T3);
        }
        // Fast algo for adding 2 Extended Points.
        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
        // Cost: 9M + 1*a + 1*d + 7add.
        add(other) {
          aextpoint(other);
          const { a, d } = CURVE;
          const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
          const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
          const A = modP(X1 * X2);
          const B = modP(Y1 * Y2);
          const C = modP(T1 * d * T2);
          const D = modP(Z1 * Z2);
          const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
          const F = D - C;
          const G = D + C;
          const H = modP(B - a * A);
          const X3 = modP(E * F);
          const Y3 = modP(G * H);
          const T3 = modP(E * H);
          const Z3 = modP(F * G);
          return new Point(X3, Y3, Z3, T3);
        }
        subtract(other) {
          return this.add(other.negate());
        }
        // Constant-time multiplication.
        multiply(scalar) {
          if (!Fn.isValidNot0(scalar))
            throw new Error("invalid scalar: expected 1 <= sc < curve.n");
          const { p, f } = wnaf.cached(this, scalar, (p2) => (0, curve_ts_1.normalizeZ)(Point, p2));
          return (0, curve_ts_1.normalizeZ)(Point, [p, f])[0];
        }
        // Non-constant-time multiplication. Uses double-and-add algorithm.
        // It's faster, but should only be used when you don't care about
        // an exposed private key e.g. sig verification.
        // Does NOT allow scalars higher than CURVE.n.
        // Accepts optional accumulator to merge with multiply (important for sparse scalars)
        multiplyUnsafe(scalar, acc = Point.ZERO) {
          if (!Fn.isValid(scalar))
            throw new Error("invalid scalar: expected 0 <= sc < curve.n");
          if (scalar === _0n)
            return Point.ZERO;
          if (this.is0() || scalar === _1n)
            return this;
          return wnaf.unsafe(this, scalar, (p) => (0, curve_ts_1.normalizeZ)(Point, p), acc);
        }
        // Checks if point is of small order.
        // If you add something to small order point, you will have "dirty"
        // point with torsion component.
        // Multiplies point by cofactor and checks if the result is 0.
        isSmallOrder() {
          return this.multiplyUnsafe(cofactor).is0();
        }
        // Multiplies point by curve order and checks if the result is 0.
        // Returns `false` is the point is dirty.
        isTorsionFree() {
          return wnaf.unsafe(this, CURVE.n).is0();
        }
        // Converts Extended point to default (x, y) coordinates.
        // Can accept precomputed Z^-1 - for example, from invertBatch.
        toAffine(invertedZ) {
          return toAffineMemo(this, invertedZ);
        }
        clearCofactor() {
          if (cofactor === _1n)
            return this;
          return this.multiplyUnsafe(cofactor);
        }
        toBytes() {
          const { x, y } = this.toAffine();
          const bytes = Fp.toBytes(y);
          bytes[bytes.length - 1] |= x & _1n ? 128 : 0;
          return bytes;
        }
        toHex() {
          return (0, utils_ts_1.bytesToHex)(this.toBytes());
        }
        toString() {
          return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
        }
        // TODO: remove
        get ex() {
          return this.X;
        }
        get ey() {
          return this.Y;
        }
        get ez() {
          return this.Z;
        }
        get et() {
          return this.T;
        }
        static normalizeZ(points) {
          return (0, curve_ts_1.normalizeZ)(Point, points);
        }
        static msm(points, scalars) {
          return (0, curve_ts_1.pippenger)(Point, Fn, points, scalars);
        }
        _setWindowSize(windowSize) {
          this.precompute(windowSize);
        }
        toRawBytes() {
          return this.toBytes();
        }
      }
      Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n, modP(CURVE.Gx * CURVE.Gy));
      Point.ZERO = new Point(_0n, _1n, _1n, _0n);
      Point.Fp = Fp;
      Point.Fn = Fn;
      const wnaf = new curve_ts_1.wNAF(Point, Fn.BITS);
      Point.BASE.precompute(8);
      return Point;
    }
    var PrimeEdwardsPoint = class {
      constructor(ep) {
        this.ep = ep;
      }
      // Static methods that must be implemented by subclasses
      static fromBytes(_bytes) {
        (0, utils_ts_1.notImplemented)();
      }
      static fromHex(_hex) {
        (0, utils_ts_1.notImplemented)();
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      // Common implementations
      clearCofactor() {
        return this;
      }
      assertValidity() {
        this.ep.assertValidity();
      }
      toAffine(invertedZ) {
        return this.ep.toAffine(invertedZ);
      }
      toHex() {
        return (0, utils_ts_1.bytesToHex)(this.toBytes());
      }
      toString() {
        return this.toHex();
      }
      isTorsionFree() {
        return true;
      }
      isSmallOrder() {
        return false;
      }
      add(other) {
        this.assertSame(other);
        return this.init(this.ep.add(other.ep));
      }
      subtract(other) {
        this.assertSame(other);
        return this.init(this.ep.subtract(other.ep));
      }
      multiply(scalar) {
        return this.init(this.ep.multiply(scalar));
      }
      multiplyUnsafe(scalar) {
        return this.init(this.ep.multiplyUnsafe(scalar));
      }
      double() {
        return this.init(this.ep.double());
      }
      negate() {
        return this.init(this.ep.negate());
      }
      precompute(windowSize, isLazy) {
        return this.init(this.ep.precompute(windowSize, isLazy));
      }
      /** @deprecated use `toBytes` */
      toRawBytes() {
        return this.toBytes();
      }
    };
    exports$1.PrimeEdwardsPoint = PrimeEdwardsPoint;
    function eddsa(Point, cHash, eddsaOpts = {}) {
      if (typeof cHash !== "function")
        throw new Error('"hash" function param is required');
      (0, utils_ts_1._validateObject)(eddsaOpts, {}, {
        adjustScalarBytes: "function",
        randomBytes: "function",
        domain: "function",
        prehash: "function",
        mapToCurve: "function"
      });
      const { prehash } = eddsaOpts;
      const { BASE, Fp, Fn } = Point;
      const randomBytes2 = eddsaOpts.randomBytes || utils_ts_1.randomBytes;
      const adjustScalarBytes = eddsaOpts.adjustScalarBytes || ((bytes) => bytes);
      const domain = eddsaOpts.domain || ((data, ctx, phflag) => {
        (0, utils_ts_1._abool2)(phflag, "phflag");
        if (ctx.length || phflag)
          throw new Error("Contexts/pre-hash are not supported");
        return data;
      });
      function modN_LE(hash2) {
        return Fn.create((0, utils_ts_1.bytesToNumberLE)(hash2));
      }
      function getPrivateScalar(key) {
        const len = lengths.secretKey;
        key = (0, utils_ts_1.ensureBytes)("private key", key, len);
        const hashed = (0, utils_ts_1.ensureBytes)("hashed private key", cHash(key), 2 * len);
        const head = adjustScalarBytes(hashed.slice(0, len));
        const prefix = hashed.slice(len, 2 * len);
        const scalar = modN_LE(head);
        return { head, prefix, scalar };
      }
      function getExtendedPublicKey(secretKey) {
        const { head, prefix, scalar } = getPrivateScalar(secretKey);
        const point = BASE.multiply(scalar);
        const pointBytes = point.toBytes();
        return { head, prefix, scalar, point, pointBytes };
      }
      function getPublicKey(secretKey) {
        return getExtendedPublicKey(secretKey).pointBytes;
      }
      function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
        const msg = (0, utils_ts_1.concatBytes)(...msgs);
        return modN_LE(cHash(domain(msg, (0, utils_ts_1.ensureBytes)("context", context), !!prehash)));
      }
      function sign(msg, secretKey, options = {}) {
        msg = (0, utils_ts_1.ensureBytes)("message", msg);
        if (prehash)
          msg = prehash(msg);
        const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
        const r = hashDomainToScalar(options.context, prefix, msg);
        const R = BASE.multiply(r).toBytes();
        const k = hashDomainToScalar(options.context, R, pointBytes, msg);
        const s = Fn.create(r + k * scalar);
        if (!Fn.isValid(s))
          throw new Error("sign failed: invalid s");
        const rs = (0, utils_ts_1.concatBytes)(R, Fn.toBytes(s));
        return (0, utils_ts_1._abytes2)(rs, lengths.signature, "result");
      }
      const verifyOpts = { zip215: true };
      function verify2(sig, msg, publicKey, options = verifyOpts) {
        const { context, zip215 } = options;
        const len = lengths.signature;
        sig = (0, utils_ts_1.ensureBytes)("signature", sig, len);
        msg = (0, utils_ts_1.ensureBytes)("message", msg);
        publicKey = (0, utils_ts_1.ensureBytes)("publicKey", publicKey, lengths.publicKey);
        if (zip215 !== void 0)
          (0, utils_ts_1._abool2)(zip215, "zip215");
        if (prehash)
          msg = prehash(msg);
        const mid = len / 2;
        const r = sig.subarray(0, mid);
        const s = (0, utils_ts_1.bytesToNumberLE)(sig.subarray(mid, len));
        let A, R, SB;
        try {
          A = Point.fromBytes(publicKey, zip215);
          R = Point.fromBytes(r, zip215);
          SB = BASE.multiplyUnsafe(s);
        } catch (error) {
          return false;
        }
        if (!zip215 && A.isSmallOrder())
          return false;
        const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
        const RkA = R.add(A.multiplyUnsafe(k));
        return RkA.subtract(SB).clearCofactor().is0();
      }
      const _size = Fp.BYTES;
      const lengths = {
        secretKey: _size,
        publicKey: _size,
        signature: 2 * _size,
        seed: _size
      };
      function randomSecretKey(seed = randomBytes2(lengths.seed)) {
        return (0, utils_ts_1._abytes2)(seed, lengths.seed, "seed");
      }
      function keygen(seed) {
        const secretKey = utils.randomSecretKey(seed);
        return { secretKey, publicKey: getPublicKey(secretKey) };
      }
      function isValidSecretKey(key) {
        return (0, utils_ts_1.isBytes)(key) && key.length === Fn.BYTES;
      }
      function isValidPublicKey(key, zip215) {
        try {
          return !!Point.fromBytes(key, zip215);
        } catch (error) {
          return false;
        }
      }
      const utils = {
        getExtendedPublicKey,
        randomSecretKey,
        isValidSecretKey,
        isValidPublicKey,
        /**
         * Converts ed public key to x public key. Uses formula:
         * - ed25519:
         *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
         *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
         * - ed448:
         *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
         *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
         */
        toMontgomery(publicKey) {
          const { y } = Point.fromBytes(publicKey);
          const size = lengths.publicKey;
          const is25519 = size === 32;
          if (!is25519 && size !== 57)
            throw new Error("only defined for 25519 and 448");
          const u = is25519 ? Fp.div(_1n + y, _1n - y) : Fp.div(y - _1n, y + _1n);
          return Fp.toBytes(u);
        },
        toMontgomerySecret(secretKey) {
          const size = lengths.secretKey;
          (0, utils_ts_1._abytes2)(secretKey, size);
          const hashed = cHash(secretKey.subarray(0, size));
          return adjustScalarBytes(hashed).subarray(0, size);
        },
        /** @deprecated */
        randomPrivateKey: randomSecretKey,
        /** @deprecated */
        precompute(windowSize = 8, point = Point.BASE) {
          return point.precompute(windowSize, false);
        }
      };
      return Object.freeze({
        keygen,
        getPublicKey,
        sign,
        verify: verify2,
        utils,
        Point,
        lengths
      });
    }
    function _eddsa_legacy_opts_to_new(c) {
      const CURVE = {
        a: c.a,
        d: c.d,
        p: c.Fp.ORDER,
        n: c.n,
        h: c.h,
        Gx: c.Gx,
        Gy: c.Gy
      };
      const Fp = c.Fp;
      const Fn = (0, modular_ts_1.Field)(CURVE.n, c.nBitLength, true);
      const curveOpts = { Fp, Fn, uvRatio: c.uvRatio };
      const eddsaOpts = {
        randomBytes: c.randomBytes,
        adjustScalarBytes: c.adjustScalarBytes,
        domain: c.domain,
        prehash: c.prehash,
        mapToCurve: c.mapToCurve
      };
      return { CURVE, curveOpts, hash: c.hash, eddsaOpts };
    }
    function _eddsa_new_output_to_legacy(c, eddsa2) {
      const Point = eddsa2.Point;
      const legacy = Object.assign({}, eddsa2, {
        ExtendedPoint: Point,
        CURVE: c,
        nBitLength: Point.Fn.BITS,
        nByteLength: Point.Fn.BYTES
      });
      return legacy;
    }
    function twistedEdwards(c) {
      const { CURVE, curveOpts, hash: hash2, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
      const Point = edwards(CURVE, curveOpts);
      const EDDSA = eddsa(Point, hash2, eddsaOpts);
      return _eddsa_new_output_to_legacy(c, EDDSA);
    }
  }
});

// node_modules/@noble/curves/abstract/montgomery.js
var require_montgomery = __commonJS({
  "node_modules/@noble/curves/abstract/montgomery.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.montgomery = montgomery;
    var utils_ts_1 = require_utils4();
    var modular_ts_1 = require_modular();
    var _0n = BigInt(0);
    var _1n = BigInt(1);
    var _2n = BigInt(2);
    function validateOpts(curve) {
      (0, utils_ts_1._validateObject)(curve, {
        adjustScalarBytes: "function",
        powPminus2: "function"
      });
      return Object.freeze({ ...curve });
    }
    function montgomery(curveDef) {
      const CURVE = validateOpts(curveDef);
      const { P, type, adjustScalarBytes, powPminus2, randomBytes: rand } = CURVE;
      const is25519 = type === "x25519";
      if (!is25519 && type !== "x448")
        throw new Error("invalid type");
      const randomBytes_ = rand || utils_ts_1.randomBytes;
      const montgomeryBits = is25519 ? 255 : 448;
      const fieldLen = is25519 ? 32 : 56;
      const Gu = is25519 ? BigInt(9) : BigInt(5);
      const a24 = is25519 ? BigInt(121665) : BigInt(39081);
      const minScalar = is25519 ? _2n ** BigInt(254) : _2n ** BigInt(447);
      const maxAdded = is25519 ? BigInt(8) * _2n ** BigInt(251) - _1n : BigInt(4) * _2n ** BigInt(445) - _1n;
      const maxScalar = minScalar + maxAdded + _1n;
      const modP = (n) => (0, modular_ts_1.mod)(n, P);
      const GuBytes = encodeU(Gu);
      function encodeU(u) {
        return (0, utils_ts_1.numberToBytesLE)(modP(u), fieldLen);
      }
      function decodeU(u) {
        const _u = (0, utils_ts_1.ensureBytes)("u coordinate", u, fieldLen);
        if (is25519)
          _u[31] &= 127;
        return modP((0, utils_ts_1.bytesToNumberLE)(_u));
      }
      function decodeScalar(scalar) {
        return (0, utils_ts_1.bytesToNumberLE)(adjustScalarBytes((0, utils_ts_1.ensureBytes)("scalar", scalar, fieldLen)));
      }
      function scalarMult(scalar, u) {
        const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
        if (pu === _0n)
          throw new Error("invalid private or public key received");
        return encodeU(pu);
      }
      function scalarMultBase(scalar) {
        return scalarMult(scalar, GuBytes);
      }
      function cswap(swap, x_2, x_3) {
        const dummy = modP(swap * (x_2 - x_3));
        x_2 = modP(x_2 - dummy);
        x_3 = modP(x_3 + dummy);
        return { x_2, x_3 };
      }
      function montgomeryLadder(u, scalar) {
        (0, utils_ts_1.aInRange)("u", u, _0n, P);
        (0, utils_ts_1.aInRange)("scalar", scalar, minScalar, maxScalar);
        const k = scalar;
        const x_1 = u;
        let x_2 = _1n;
        let z_2 = _0n;
        let x_3 = u;
        let z_3 = _1n;
        let swap = _0n;
        for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
          const k_t = k >> t & _1n;
          swap ^= k_t;
          ({ x_2, x_3 } = cswap(swap, x_2, x_3));
          ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
          swap = k_t;
          const A = x_2 + z_2;
          const AA = modP(A * A);
          const B = x_2 - z_2;
          const BB = modP(B * B);
          const E = AA - BB;
          const C = x_3 + z_3;
          const D = x_3 - z_3;
          const DA = modP(D * A);
          const CB = modP(C * B);
          const dacb = DA + CB;
          const da_cb = DA - CB;
          x_3 = modP(dacb * dacb);
          z_3 = modP(x_1 * modP(da_cb * da_cb));
          x_2 = modP(AA * BB);
          z_2 = modP(E * (AA + modP(a24 * E)));
        }
        ({ x_2, x_3 } = cswap(swap, x_2, x_3));
        ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
        const z22 = powPminus2(z_2);
        return modP(x_2 * z22);
      }
      const lengths = {
        secretKey: fieldLen,
        publicKey: fieldLen,
        seed: fieldLen
      };
      const randomSecretKey = (seed = randomBytes_(fieldLen)) => {
        (0, utils_ts_1.abytes)(seed, lengths.seed);
        return seed;
      };
      function keygen(seed) {
        const secretKey = randomSecretKey(seed);
        return { secretKey, publicKey: scalarMultBase(secretKey) };
      }
      const utils = {
        randomSecretKey,
        randomPrivateKey: randomSecretKey
      };
      return {
        keygen,
        getSharedSecret: (secretKey, publicKey) => scalarMult(secretKey, publicKey),
        getPublicKey: (secretKey) => scalarMultBase(secretKey),
        scalarMult,
        scalarMultBase,
        utils,
        GuBytes: GuBytes.slice(),
        lengths
      };
    }
  }
});

// node_modules/@noble/curves/ed25519.js
var require_ed25519 = __commonJS({
  "node_modules/@noble/curves/ed25519.js"(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.hash_to_ristretto255 = exports$1.hashToRistretto255 = exports$1.encodeToCurve = exports$1.hashToCurve = exports$1.RistrettoPoint = exports$1.edwardsToMontgomery = exports$1.ED25519_TORSION_SUBGROUP = exports$1.ristretto255_hasher = exports$1.ristretto255 = exports$1.ed25519_hasher = exports$1.x25519 = exports$1.ed25519ph = exports$1.ed25519ctx = exports$1.ed25519 = void 0;
    exports$1.edwardsToMontgomeryPub = edwardsToMontgomeryPub;
    exports$1.edwardsToMontgomeryPriv = edwardsToMontgomeryPriv;
    var sha2_js_1 = require_sha2();
    var utils_js_1 = require_utils();
    var curve_ts_1 = require_curve();
    var edwards_ts_1 = require_edwards();
    var hash_to_curve_ts_1 = require_hash_to_curve();
    var modular_ts_1 = require_modular();
    var montgomery_ts_1 = require_montgomery();
    var utils_ts_1 = require_utils4();
    var _0n = /* @__PURE__ */ BigInt(0);
    var _1n = BigInt(1);
    var _2n = BigInt(2);
    var _3n = BigInt(3);
    var _5n = BigInt(5);
    var _8n = BigInt(8);
    var ed25519_CURVE_p = BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    var ed25519_CURVE = /* @__PURE__ */ (() => ({
      p: ed25519_CURVE_p,
      n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
      h: _8n,
      a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
      d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
      Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
      Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
    }))();
    function ed25519_pow_2_252_3(x) {
      const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
      const P = ed25519_CURVE_p;
      const x2 = x * x % P;
      const b2 = x2 * x % P;
      const b4 = (0, modular_ts_1.pow2)(b2, _2n, P) * b2 % P;
      const b5 = (0, modular_ts_1.pow2)(b4, _1n, P) * x % P;
      const b10 = (0, modular_ts_1.pow2)(b5, _5n, P) * b5 % P;
      const b20 = (0, modular_ts_1.pow2)(b10, _10n, P) * b10 % P;
      const b40 = (0, modular_ts_1.pow2)(b20, _20n, P) * b20 % P;
      const b80 = (0, modular_ts_1.pow2)(b40, _40n, P) * b40 % P;
      const b160 = (0, modular_ts_1.pow2)(b80, _80n, P) * b80 % P;
      const b240 = (0, modular_ts_1.pow2)(b160, _80n, P) * b80 % P;
      const b250 = (0, modular_ts_1.pow2)(b240, _10n, P) * b10 % P;
      const pow_p_5_8 = (0, modular_ts_1.pow2)(b250, _2n, P) * x % P;
      return { pow_p_5_8, b2 };
    }
    function adjustScalarBytes(bytes) {
      bytes[0] &= 248;
      bytes[31] &= 127;
      bytes[31] |= 64;
      return bytes;
    }
    var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
    function uvRatio(u, v) {
      const P = ed25519_CURVE_p;
      const v3 = (0, modular_ts_1.mod)(v * v * v, P);
      const v7 = (0, modular_ts_1.mod)(v3 * v3 * v, P);
      const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
      let x = (0, modular_ts_1.mod)(u * v3 * pow, P);
      const vx2 = (0, modular_ts_1.mod)(v * x * x, P);
      const root1 = x;
      const root2 = (0, modular_ts_1.mod)(x * ED25519_SQRT_M1, P);
      const useRoot1 = vx2 === u;
      const useRoot2 = vx2 === (0, modular_ts_1.mod)(-u, P);
      const noRoot = vx2 === (0, modular_ts_1.mod)(-u * ED25519_SQRT_M1, P);
      if (useRoot1)
        x = root1;
      if (useRoot2 || noRoot)
        x = root2;
      if ((0, modular_ts_1.isNegativeLE)(x, P))
        x = (0, modular_ts_1.mod)(-x, P);
      return { isValid: useRoot1 || useRoot2, value: x };
    }
    var Fp = /* @__PURE__ */ (() => (0, modular_ts_1.Field)(ed25519_CURVE.p, { isLE: true }))();
    var Fn = /* @__PURE__ */ (() => (0, modular_ts_1.Field)(ed25519_CURVE.n, { isLE: true }))();
    var ed25519Defaults = /* @__PURE__ */ (() => ({
      ...ed25519_CURVE,
      Fp,
      hash: sha2_js_1.sha512,
      adjustScalarBytes,
      // dom2
      // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
      // Constant-time, u/√v
      uvRatio
    }))();
    exports$1.ed25519 = (() => (0, edwards_ts_1.twistedEdwards)(ed25519Defaults))();
    function ed25519_domain(data, ctx, phflag) {
      if (ctx.length > 255)
        throw new Error("Context is too big");
      return (0, utils_js_1.concatBytes)((0, utils_js_1.utf8ToBytes)("SigEd25519 no Ed25519 collisions"), new Uint8Array([phflag ? 1 : 0, ctx.length]), ctx, data);
    }
    exports$1.ed25519ctx = (() => (0, edwards_ts_1.twistedEdwards)({
      ...ed25519Defaults,
      domain: ed25519_domain
    }))();
    exports$1.ed25519ph = (() => (0, edwards_ts_1.twistedEdwards)(Object.assign({}, ed25519Defaults, {
      domain: ed25519_domain,
      prehash: sha2_js_1.sha512
    })))();
    exports$1.x25519 = (() => {
      const P = Fp.ORDER;
      return (0, montgomery_ts_1.montgomery)({
        P,
        type: "x25519",
        powPminus2: (x) => {
          const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
          return (0, modular_ts_1.mod)((0, modular_ts_1.pow2)(pow_p_5_8, _3n, P) * b2, P);
        },
        adjustScalarBytes
      });
    })();
    var ELL2_C1 = /* @__PURE__ */ (() => (ed25519_CURVE_p + _3n) / _8n)();
    var ELL2_C2 = /* @__PURE__ */ (() => Fp.pow(_2n, ELL2_C1))();
    var ELL2_C3 = /* @__PURE__ */ (() => Fp.sqrt(Fp.neg(Fp.ONE)))();
    function map_to_curve_elligator2_curve25519(u) {
      const ELL2_C4 = (ed25519_CURVE_p - _5n) / _8n;
      const ELL2_J = BigInt(486662);
      let tv1 = Fp.sqr(u);
      tv1 = Fp.mul(tv1, _2n);
      let xd = Fp.add(tv1, Fp.ONE);
      let x1n = Fp.neg(ELL2_J);
      let tv2 = Fp.sqr(xd);
      let gxd = Fp.mul(tv2, xd);
      let gx1 = Fp.mul(tv1, ELL2_J);
      gx1 = Fp.mul(gx1, x1n);
      gx1 = Fp.add(gx1, tv2);
      gx1 = Fp.mul(gx1, x1n);
      let tv3 = Fp.sqr(gxd);
      tv2 = Fp.sqr(tv3);
      tv3 = Fp.mul(tv3, gxd);
      tv3 = Fp.mul(tv3, gx1);
      tv2 = Fp.mul(tv2, tv3);
      let y11 = Fp.pow(tv2, ELL2_C4);
      y11 = Fp.mul(y11, tv3);
      let y12 = Fp.mul(y11, ELL2_C3);
      tv2 = Fp.sqr(y11);
      tv2 = Fp.mul(tv2, gxd);
      let e1 = Fp.eql(tv2, gx1);
      let y1 = Fp.cmov(y12, y11, e1);
      let x2n = Fp.mul(x1n, tv1);
      let y21 = Fp.mul(y11, u);
      y21 = Fp.mul(y21, ELL2_C2);
      let y22 = Fp.mul(y21, ELL2_C3);
      let gx2 = Fp.mul(gx1, tv1);
      tv2 = Fp.sqr(y21);
      tv2 = Fp.mul(tv2, gxd);
      let e2 = Fp.eql(tv2, gx2);
      let y2 = Fp.cmov(y22, y21, e2);
      tv2 = Fp.sqr(y1);
      tv2 = Fp.mul(tv2, gxd);
      let e3 = Fp.eql(tv2, gx1);
      let xn = Fp.cmov(x2n, x1n, e3);
      let y = Fp.cmov(y2, y1, e3);
      let e4 = Fp.isOdd(y);
      y = Fp.cmov(y, Fp.neg(y), e3 !== e4);
      return { xMn: xn, xMd: xd, yMn: y, yMd: _1n };
    }
    var ELL2_C1_EDWARDS = /* @__PURE__ */ (() => (0, modular_ts_1.FpSqrtEven)(Fp, Fp.neg(BigInt(486664))))();
    function map_to_curve_elligator2_edwards25519(u) {
      const { xMn, xMd, yMn, yMd } = map_to_curve_elligator2_curve25519(u);
      let xn = Fp.mul(xMn, yMd);
      xn = Fp.mul(xn, ELL2_C1_EDWARDS);
      let xd = Fp.mul(xMd, yMn);
      let yn = Fp.sub(xMn, xMd);
      let yd = Fp.add(xMn, xMd);
      let tv1 = Fp.mul(xd, yd);
      let e = Fp.eql(tv1, Fp.ZERO);
      xn = Fp.cmov(xn, Fp.ZERO, e);
      xd = Fp.cmov(xd, Fp.ONE, e);
      yn = Fp.cmov(yn, Fp.ONE, e);
      yd = Fp.cmov(yd, Fp.ONE, e);
      const [xd_inv, yd_inv] = (0, modular_ts_1.FpInvertBatch)(Fp, [xd, yd], true);
      return { x: Fp.mul(xn, xd_inv), y: Fp.mul(yn, yd_inv) };
    }
    exports$1.ed25519_hasher = (() => (0, hash_to_curve_ts_1.createHasher)(exports$1.ed25519.Point, (scalars) => map_to_curve_elligator2_edwards25519(scalars[0]), {
      DST: "edwards25519_XMD:SHA-512_ELL2_RO_",
      encodeDST: "edwards25519_XMD:SHA-512_ELL2_NU_",
      p: ed25519_CURVE_p,
      m: 1,
      k: 128,
      expand: "xmd",
      hash: sha2_js_1.sha512
    }))();
    var SQRT_M1 = ED25519_SQRT_M1;
    var SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt("25063068953384623474111414158702152701244531502492656460079210482610430750235");
    var INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt("54469307008909316920995813868745141605393597292927456921205312896311721017578");
    var ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt("1159843021668779879193775521855586647937357759715417654439879720876111806838");
    var D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt("40440834346308536858101042469323190826248399146238708352240133220865137265952");
    var invertSqrt = (number) => uvRatio(_1n, number);
    var MAX_255B = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    var bytes255ToNumberLE = (bytes) => exports$1.ed25519.Point.Fp.create((0, utils_ts_1.bytesToNumberLE)(bytes) & MAX_255B);
    function calcElligatorRistrettoMap(r0) {
      const { d } = ed25519_CURVE;
      const P = ed25519_CURVE_p;
      const mod = (n) => Fp.create(n);
      const r = mod(SQRT_M1 * r0 * r0);
      const Ns = mod((r + _1n) * ONE_MINUS_D_SQ);
      let c = BigInt(-1);
      const D = mod((c - d * r) * mod(r + d));
      let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
      let s_ = mod(s * r0);
      if (!(0, modular_ts_1.isNegativeLE)(s_, P))
        s_ = mod(-s_);
      if (!Ns_D_is_sq)
        s = s_;
      if (!Ns_D_is_sq)
        c = r;
      const Nt = mod(c * (r - _1n) * D_MINUS_ONE_SQ - D);
      const s2 = s * s;
      const W0 = mod((s + s) * D);
      const W1 = mod(Nt * SQRT_AD_MINUS_ONE);
      const W2 = mod(_1n - s2);
      const W3 = mod(_1n + s2);
      return new exports$1.ed25519.Point(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
    }
    function ristretto255_map(bytes) {
      (0, utils_js_1.abytes)(bytes, 64);
      const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
      const R1 = calcElligatorRistrettoMap(r1);
      const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
      const R2 = calcElligatorRistrettoMap(r2);
      return new _RistrettoPoint(R1.add(R2));
    }
    var _RistrettoPoint = class __RistrettoPoint extends edwards_ts_1.PrimeEdwardsPoint {
      constructor(ep) {
        super(ep);
      }
      static fromAffine(ap) {
        return new __RistrettoPoint(exports$1.ed25519.Point.fromAffine(ap));
      }
      assertSame(other) {
        if (!(other instanceof __RistrettoPoint))
          throw new Error("RistrettoPoint expected");
      }
      init(ep) {
        return new __RistrettoPoint(ep);
      }
      /** @deprecated use `import { ristretto255_hasher } from '@noble/curves/ed25519.js';` */
      static hashToCurve(hex) {
        return ristretto255_map((0, utils_ts_1.ensureBytes)("ristrettoHash", hex, 64));
      }
      static fromBytes(bytes) {
        (0, utils_js_1.abytes)(bytes, 32);
        const { a, d } = ed25519_CURVE;
        const P = ed25519_CURVE_p;
        const mod = (n) => Fp.create(n);
        const s = bytes255ToNumberLE(bytes);
        if (!(0, utils_ts_1.equalBytes)(Fp.toBytes(s), bytes) || (0, modular_ts_1.isNegativeLE)(s, P))
          throw new Error("invalid ristretto255 encoding 1");
        const s2 = mod(s * s);
        const u1 = mod(_1n + a * s2);
        const u2 = mod(_1n - a * s2);
        const u1_2 = mod(u1 * u1);
        const u2_2 = mod(u2 * u2);
        const v = mod(a * d * u1_2 - u2_2);
        const { isValid, value: I } = invertSqrt(mod(v * u2_2));
        const Dx = mod(I * u2);
        const Dy = mod(I * Dx * v);
        let x = mod((s + s) * Dx);
        if ((0, modular_ts_1.isNegativeLE)(x, P))
          x = mod(-x);
        const y = mod(u1 * Dy);
        const t = mod(x * y);
        if (!isValid || (0, modular_ts_1.isNegativeLE)(t, P) || y === _0n)
          throw new Error("invalid ristretto255 encoding 2");
        return new __RistrettoPoint(new exports$1.ed25519.Point(x, y, _1n, t));
      }
      /**
       * Converts ristretto-encoded string to ristretto point.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
       * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
       */
      static fromHex(hex) {
        return __RistrettoPoint.fromBytes((0, utils_ts_1.ensureBytes)("ristrettoHex", hex, 32));
      }
      static msm(points, scalars) {
        return (0, curve_ts_1.pippenger)(__RistrettoPoint, exports$1.ed25519.Point.Fn, points, scalars);
      }
      /**
       * Encodes ristretto point to Uint8Array.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
       */
      toBytes() {
        let { X, Y, Z, T } = this.ep;
        const P = ed25519_CURVE_p;
        const mod = (n) => Fp.create(n);
        const u1 = mod(mod(Z + Y) * mod(Z - Y));
        const u2 = mod(X * Y);
        const u2sq = mod(u2 * u2);
        const { value: invsqrt } = invertSqrt(mod(u1 * u2sq));
        const D1 = mod(invsqrt * u1);
        const D2 = mod(invsqrt * u2);
        const zInv = mod(D1 * D2 * T);
        let D;
        if ((0, modular_ts_1.isNegativeLE)(T * zInv, P)) {
          let _x = mod(Y * SQRT_M1);
          let _y = mod(X * SQRT_M1);
          X = _x;
          Y = _y;
          D = mod(D1 * INVSQRT_A_MINUS_D);
        } else {
          D = D2;
        }
        if ((0, modular_ts_1.isNegativeLE)(X * zInv, P))
          Y = mod(-Y);
        let s = mod((Z - Y) * D);
        if ((0, modular_ts_1.isNegativeLE)(s, P))
          s = mod(-s);
        return Fp.toBytes(s);
      }
      /**
       * Compares two Ristretto points.
       * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
       */
      equals(other) {
        this.assertSame(other);
        const { X: X1, Y: Y1 } = this.ep;
        const { X: X2, Y: Y2 } = other.ep;
        const mod = (n) => Fp.create(n);
        const one = mod(X1 * Y2) === mod(Y1 * X2);
        const two = mod(Y1 * Y2) === mod(X1 * X2);
        return one || two;
      }
      is0() {
        return this.equals(__RistrettoPoint.ZERO);
      }
    };
    _RistrettoPoint.BASE = /* @__PURE__ */ (() => new _RistrettoPoint(exports$1.ed25519.Point.BASE))();
    _RistrettoPoint.ZERO = /* @__PURE__ */ (() => new _RistrettoPoint(exports$1.ed25519.Point.ZERO))();
    _RistrettoPoint.Fp = /* @__PURE__ */ (() => Fp)();
    _RistrettoPoint.Fn = /* @__PURE__ */ (() => Fn)();
    exports$1.ristretto255 = { Point: _RistrettoPoint };
    exports$1.ristretto255_hasher = {
      hashToCurve(msg, options) {
        const DST = options?.DST || "ristretto255_XMD:SHA-512_R255MAP_RO_";
        const xmd = (0, hash_to_curve_ts_1.expand_message_xmd)(msg, DST, 64, sha2_js_1.sha512);
        return ristretto255_map(xmd);
      },
      hashToScalar(msg, options = { DST: hash_to_curve_ts_1._DST_scalar }) {
        const xmd = (0, hash_to_curve_ts_1.expand_message_xmd)(msg, options.DST, 64, sha2_js_1.sha512);
        return Fn.create((0, utils_ts_1.bytesToNumberLE)(xmd));
      }
    };
    exports$1.ED25519_TORSION_SUBGROUP = [
      "0100000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
    ];
    function edwardsToMontgomeryPub(edwardsPub) {
      return exports$1.ed25519.utils.toMontgomery((0, utils_ts_1.ensureBytes)("pub", edwardsPub));
    }
    exports$1.edwardsToMontgomery = edwardsToMontgomeryPub;
    function edwardsToMontgomeryPriv(edwardsPriv) {
      return exports$1.ed25519.utils.toMontgomerySecret((0, utils_ts_1.ensureBytes)("pub", edwardsPriv));
    }
    exports$1.RistrettoPoint = _RistrettoPoint;
    exports$1.hashToCurve = (() => exports$1.ed25519_hasher.hashToCurve)();
    exports$1.encodeToCurve = (() => exports$1.ed25519_hasher.encodeToCurve)();
    exports$1.hashToRistretto255 = (() => exports$1.ristretto255_hasher.hashToCurve)();
    exports$1.hash_to_ristretto255 = (() => exports$1.ristretto255_hasher.hashToCurve)();
  }
});

// node_modules/ripple-keypairs/dist/signing-schemes/ed25519/index.js
var require_ed255192 = __commonJS({
  "node_modules/ripple-keypairs/dist/signing-schemes/ed25519/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var ed25519_1 = require_ed25519();
    var utils_1 = require_utils2();
    var assert_1 = __importDefault(require_assert());
    var Sha512_1 = __importDefault(require_Sha512());
    var ED_PREFIX = "ED";
    var ed25519 = {
      deriveKeypair(entropy) {
        const rawPrivateKey = Sha512_1.default.half(entropy);
        const privateKey = ED_PREFIX + (0, utils_1.bytesToHex)(rawPrivateKey);
        const publicKey = ED_PREFIX + (0, utils_1.bytesToHex)(ed25519_1.ed25519.getPublicKey(rawPrivateKey));
        return { privateKey, publicKey };
      },
      sign(message, privateKey) {
        assert_1.default.ok(message instanceof Uint8Array, "message must be array of octets");
        assert_1.default.ok(privateKey.length === 66, "private key must be 33 bytes including prefix");
        return (0, utils_1.bytesToHex)(ed25519_1.ed25519.sign(message, privateKey.slice(2)));
      },
      verify(message, signature, publicKey) {
        assert_1.default.ok(publicKey.length === 66, "public key must be 33 bytes including prefix");
        return ed25519_1.ed25519.verify(
          signature,
          message,
          // Remove the 0xED prefix
          publicKey.slice(2),
          // By default, set zip215 to false for compatibility reasons.
          // ZIP 215 is a stricter Ed25519 signature verification scheme.
          // However, setting it to false adheres to the more commonly used
          // RFC8032 / NIST186-5 standards, making it compatible with systems
          // like the XRP Ledger.
          { zip215: false }
        );
      }
    };
    exports$1.default = ed25519;
  }
});

// node_modules/ripple-keypairs/dist/index.js
var require_dist2 = __commonJS({
  "node_modules/ripple-keypairs/dist/index.js"(exports$1) {
    var __importDefault = exports$1 && exports$1.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports$1, "__esModule", { value: true });
    exports$1.decodeSeed = exports$1.deriveNodeAddress = exports$1.deriveAddress = exports$1.verify = exports$1.sign = exports$1.deriveKeypair = exports$1.generateSeed = void 0;
    var ripple_address_codec_1 = require_dist();
    Object.defineProperty(exports$1, "decodeSeed", { enumerable: true, get: function() {
      return ripple_address_codec_1.decodeSeed;
    } });
    var ripemd160_1 = require_ripemd160();
    var sha256_1 = require_sha256();
    var utils_1 = require_utils2();
    var utils_2 = require_utils6();
    var Sha512_1 = __importDefault(require_Sha512());
    var assert_1 = __importDefault(require_assert());
    var getAlgorithmFromKey_1 = require_getAlgorithmFromKey();
    var secp256k1_1 = __importDefault(require_secp256k12());
    var ed25519_1 = __importDefault(require_ed255192());
    function getSigningScheme(algorithm) {
      const schemes = { "ecdsa-secp256k1": secp256k1_1.default, ed25519: ed25519_1.default };
      return schemes[algorithm];
    }
    function generateSeed(options = {}) {
      assert_1.default.ok(!options.entropy || options.entropy.length >= 16, "entropy too short");
      const entropy = options.entropy ? options.entropy.slice(0, 16) : (0, utils_1.randomBytes)(16);
      const type = options.algorithm === "ed25519" ? "ed25519" : "secp256k1";
      return (0, ripple_address_codec_1.encodeSeed)(entropy, type);
    }
    exports$1.generateSeed = generateSeed;
    function deriveKeypair(seed, options) {
      var _a;
      const decoded = (0, ripple_address_codec_1.decodeSeed)(seed);
      const proposedAlgorithm = (_a = options === null || options === void 0 ? void 0 : options.algorithm) !== null && _a !== void 0 ? _a : decoded.type;
      const algorithm = proposedAlgorithm === "ed25519" ? "ed25519" : "ecdsa-secp256k1";
      const scheme = getSigningScheme(algorithm);
      const keypair = scheme.deriveKeypair(decoded.bytes, options);
      const messageToVerify = Sha512_1.default.half("This test message should verify.");
      const signature = scheme.sign(messageToVerify, keypair.privateKey);
      if (!scheme.verify(messageToVerify, signature, keypair.publicKey)) {
        throw new Error("derived keypair did not generate verifiable signature");
      }
      return keypair;
    }
    exports$1.deriveKeypair = deriveKeypair;
    function sign(messageHex, privateKey) {
      const algorithm = (0, getAlgorithmFromKey_1.getAlgorithmFromPrivateKey)(privateKey);
      return getSigningScheme(algorithm).sign((0, utils_1.hexToBytes)(messageHex), privateKey);
    }
    exports$1.sign = sign;
    function verify2(messageHex, signature, publicKey) {
      const algorithm = (0, getAlgorithmFromKey_1.getAlgorithmFromPublicKey)(publicKey);
      return getSigningScheme(algorithm).verify((0, utils_1.hexToBytes)(messageHex), signature, publicKey);
    }
    exports$1.verify = verify2;
    function computePublicKeyHash(publicKeyBytes) {
      return (0, ripemd160_1.ripemd160)((0, sha256_1.sha256)(publicKeyBytes));
    }
    function deriveAddressFromBytes(publicKeyBytes) {
      return (0, ripple_address_codec_1.encodeAccountID)(computePublicKeyHash(publicKeyBytes));
    }
    function deriveAddress(publicKey) {
      return deriveAddressFromBytes((0, utils_1.hexToBytes)(publicKey));
    }
    exports$1.deriveAddress = deriveAddress;
    function deriveNodeAddress(publicKey) {
      const generatorBytes = (0, ripple_address_codec_1.decodeNodePublic)(publicKey);
      const accountPublicBytes = (0, utils_2.accountPublicFromPublicGenerator)(generatorBytes);
      return deriveAddressFromBytes(accountPublicBytes);
    }
    exports$1.deriveNodeAddress = deriveNodeAddress;
  }
});
var GENESIS_CONSTANT = "XRPL-WALLET-MCP-GENESIS-V1";
var HMAC_ALGORITHM = "sha256";
var HMAC_KEY_LENGTH = 32;
var HmacKeySchema = z.instanceof(Buffer).refine(
  (buf) => buf.length === HMAC_KEY_LENGTH,
  `HMAC key must be exactly ${HMAC_KEY_LENGTH} bytes (${HMAC_KEY_LENGTH * 8} bits)`
);
var ChainStateSchema = z.object({
  sequence: z.number().int().min(0),
  previousHash: z.string().length(64).regex(/^[a-f0-9]{64}$/i)
});
var VerificationOptionsSchema = z.object({
  fullChain: z.boolean().optional(),
  startSequence: z.number().int().positive().optional(),
  endSequence: z.number().int().positive().optional(),
  recentEntries: z.number().int().positive().optional(),
  continueOnError: z.boolean().optional()
});
var HashChain = class {
  hmacKey;
  state;
  /**
   * Create a new HashChain instance
   *
   * @param hmacKey - 256-bit HMAC key (32 bytes)
   * @param initialState - Optional initial chain state (for resuming)
   * @throws Error if HMAC key is invalid
   */
  constructor(hmacKey, initialState) {
    const keyResult = HmacKeySchema.safeParse(hmacKey);
    if (!keyResult.success) {
      throw new Error(`Invalid HMAC key: ${keyResult.error.message}`);
    }
    this.hmacKey = Buffer.from(hmacKey);
    this.state = initialState ?? {
      sequence: 0,
      previousHash: this.computeGenesisHash()
    };
  }
  /**
   * Compute the genesis hash for a new chain
   *
   * The genesis hash is a well-known constant computed from the
   * GENESIS_CONSTANT using the HMAC key. This provides a verifiable
   * starting point for the chain.
   *
   * @returns Hex-encoded genesis hash
   */
  computeGenesisHash() {
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(GENESIS_CONSTANT);
    return hmac.digest("hex");
  }
  /**
   * Compute HMAC-SHA256 hash of entry data
   *
   * The hash includes all fields except 'hash' itself. Fields are
   * sorted alphabetically for deterministic serialization.
   *
   * @param data - Entry data (hash field will be ignored)
   * @returns Hex-encoded HMAC-SHA256 hash
   */
  computeHash(data) {
    const dataForHashing = {};
    for (const key of Object.keys(data).sort()) {
      if (key !== "hash") {
        dataForHashing[key] = data[key];
      }
    }
    const serialized = JSON.stringify(dataForHashing, Object.keys(dataForHashing).sort());
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(serialized);
    return hmac.digest("hex");
  }
  /**
   * Get the current chain state
   *
   * @returns Current sequence number and previous hash
   */
  getState() {
    return { ...this.state };
  }
  /**
   * Set the chain state (for resuming from storage)
   *
   * @param state - Chain state to restore
   */
  setState(state) {
    const result = ChainStateSchema.safeParse(state);
    if (!result.success) {
      throw new Error(`Invalid chain state: ${result.error.message}`);
    }
    this.state = { ...state };
  }
  /**
   * Create the next entry in the chain
   *
   * Adds integrity fields (sequence, timestamp, previousHash, hash)
   * to the provided data and updates the chain state.
   *
   * @param data - Entry data (without integrity fields)
   * @returns Complete entry with hash chain fields
   */
  createEntry(data) {
    const sequence = this.state.sequence + 1;
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
    const previousHash = this.state.previousHash;
    const entry = {
      ...data,
      sequence,
      timestamp,
      previousHash,
      hash: ""
    };
    entry.hash = this.computeHash(entry);
    this.state = {
      sequence,
      previousHash: entry.hash
    };
    return entry;
  }
  /**
   * Verify hash integrity of a single entry
   *
   * @param entry - Entry to verify
   * @param expectedPrevHash - Expected previous hash (from prior entry or genesis)
   * @returns Array of errors found (empty if valid)
   */
  verifyEntry(entry, expectedPrevHash) {
    const errors = [];
    if (expectedPrevHash !== void 0 && entry.previousHash !== expectedPrevHash) {
      errors.push({
        type: "chain_break",
        sequence: entry.sequence,
        expected: expectedPrevHash,
        actual: entry.previousHash,
        description: `Chain break: previousHash does not match prior entry's hash`
      });
    }
    const computedHash = this.computeHash(entry);
    if (computedHash !== entry.hash) {
      errors.push({
        type: "tampered_entry",
        sequence: entry.sequence,
        expected: computedHash,
        actual: entry.hash,
        description: `Entry hash mismatch: entry may have been tampered with`
      });
    }
    return errors;
  }
  /**
   * Verify a sequence of entries
   *
   * Checks:
   * 1. Sequence numbers are monotonic without gaps
   * 2. Each entry's previousHash matches prior entry's hash
   * 3. Each entry's hash can be recomputed correctly
   * 4. Timestamps are monotonically increasing
   *
   * @param entries - Array of entries to verify (must be in sequence order)
   * @param options - Verification options
   * @returns Verification result with any detected errors
   */
  verifyEntries(entries, options = {}) {
    const startTime = Date.now();
    const errors = [];
    if (entries.length === 0) {
      return {
        valid: true,
        entriesVerified: 0,
        startSequence: 0,
        endSequence: 0,
        durationMs: Date.now() - startTime,
        errors: []
      };
    }
    const firstEntry = entries[0];
    const lastEntry = entries[entries.length - 1];
    let expectedPrevHash;
    if (firstEntry.sequence === 1) {
      expectedPrevHash = this.computeGenesisHash();
    } else {
      expectedPrevHash = firstEntry.previousHash;
    }
    let expectedSequence = firstEntry.sequence;
    let lastTimestamp = /* @__PURE__ */ new Date(0);
    for (const entry of entries) {
      if (entry.sequence !== expectedSequence) {
        errors.push({
          type: "sequence_gap",
          sequence: entry.sequence,
          expected: expectedSequence,
          actual: entry.sequence,
          description: `Expected sequence ${expectedSequence}, got ${entry.sequence}`
        });
        if (!options.continueOnError) {
          expectedSequence = entry.sequence;
        }
      }
      if (entry.previousHash !== expectedPrevHash) {
        errors.push({
          type: "chain_break",
          sequence: entry.sequence,
          expected: expectedPrevHash,
          actual: entry.previousHash,
          description: `Chain break: previousHash does not match prior entry's hash`
        });
      }
      const computedHash = this.computeHash(entry);
      if (computedHash !== entry.hash) {
        errors.push({
          type: "tampered_entry",
          sequence: entry.sequence,
          expected: computedHash,
          actual: entry.hash,
          description: `Entry hash mismatch: entry may have been tampered with`
        });
      }
      const entryTime = new Date(entry.timestamp);
      if (entryTime < lastTimestamp) {
        errors.push({
          type: "invalid_timestamp",
          sequence: entry.sequence,
          expected: lastTimestamp.toISOString(),
          actual: entry.timestamp,
          description: `Timestamp is earlier than previous entry`
        });
      }
      lastTimestamp = entryTime;
      expectedPrevHash = entry.hash;
      expectedSequence = entry.sequence + 1;
    }
    return {
      valid: errors.length === 0,
      entriesVerified: entries.length,
      startSequence: firstEntry.sequence,
      endSequence: lastEntry.sequence,
      durationMs: Date.now() - startTime,
      errors
    };
  }
  /**
   * Verify that an entry correctly links to a previous entry
   *
   * @param current - Current entry to verify
   * @param previous - Previous entry in the chain
   * @returns True if chain link is valid
   */
  verifyChainLink(current, previous) {
    return current.previousHash === previous.hash;
  }
  /**
   * Dispose of the hash chain and zero out the HMAC key
   *
   * Should be called when the chain is no longer needed to
   * prevent key material from remaining in memory.
   */
  dispose() {
    this.hmacKey.fill(0);
  }
};
function isValidHmacKey(key) {
  return HmacKeySchema.safeParse(key).success;
}
function generateHmacKey() {
  const crypto2 = __require("crypto");
  return crypto2.randomBytes(HMAC_KEY_LENGTH);
}
function computeStandaloneHash(key, data) {
  const hmac = createHmac(HMAC_ALGORITHM, key);
  hmac.update(data);
  return hmac.digest("hex");
}
var DEFAULT_BASE_DIR = ".xrpl-wallet-mcp";
var AUDIT_SUBDIR = "audit";
var LOG_FILE_PREFIX = "audit-";
var LOG_FILE_EXTENSION = ".jsonl";
var LOG_FILE_MODE = 384;
var DIR_MODE = 448;
var DEFAULT_AUDIT_LOGGER_CONFIG = {
  baseDir: path2.join(process.env["HOME"] || "~", DEFAULT_BASE_DIR),
  network: "testnet",
  syncWrites: true,
  verifyOnStartup: true,
  startupVerificationEntries: 1e3
};
var AuditLogInputSchema = z.object({
  event: AuditEventTypeSchema,
  wallet_id: z.string().optional(),
  wallet_address: z.string().optional(),
  transaction_type: TransactionTypeSchema.optional(),
  amount_xrp: z.string().optional(),
  destination: z.string().optional(),
  tier: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
  policy_decision: z.enum(["allowed", "denied", "pending"]).optional(),
  tx_hash: z.string().optional(),
  context: z.string().optional()
});
var REDACTED_FIELDS = /* @__PURE__ */ new Set([
  "password",
  "seed",
  "secret",
  "privatekey",
  "private_key",
  "mnemonic",
  "passphrase",
  "encryptionkey",
  "hmackey",
  "masterkey",
  "master_key",
  "secretkey",
  "secret_key",
  "apikey",
  "api_key",
  "token",
  "bearer"
]);
var SENSITIVE_PATTERNS = [
  /^s[a-zA-Z0-9]{28}$/,
  // XRPL seed
  /^[a-f0-9]{64}$/i,
  // 256-bit hex (private key)
  /^[a-f0-9]{128}$/i,
  // 512-bit hex
  /^(abandon\s+){11}(abandon|about|above|absent)\b/i
  // BIP39 mnemonic start
];
function sanitizeForLogging(obj, depth = 0) {
  if (depth > 10) return "[MAX_DEPTH]";
  if (obj === null || obj === void 0) return obj;
  if (typeof obj === "string") {
    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.test(obj)) return "[REDACTED]";
    }
    return obj.length > 1e3 ? obj.slice(0, 100) + "...[TRUNCATED]" : obj;
  }
  if (typeof obj !== "object") return obj;
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeForLogging(item, depth + 1));
  }
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase().replace(/[-_]/g, "");
    if (REDACTED_FIELDS.has(lowerKey)) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = sanitizeForLogging(value, depth + 1);
    }
  }
  return result;
}
var AuditLogger = class _AuditLogger extends EventEmitter {
  config;
  chain;
  logDir;
  currentLogPath;
  isInitialized = false;
  writeLock = Promise.resolve();
  /**
   * Private constructor - use AuditLogger.create() factory method
   */
  constructor(hmacKey, config, chainState) {
    super();
    this.config = config;
    this.chain = new HashChain(hmacKey, chainState);
    this.logDir = path2.join(config.baseDir, config.network, AUDIT_SUBDIR);
    this.currentLogPath = this.getLogFilePath(/* @__PURE__ */ new Date());
  }
  /**
   * Create and initialize an AuditLogger instance
   *
   * Factory method ensures proper initialization:
   * 1. Loads HMAC key from provider
   * 2. Creates audit directory if needed
   * 3. Restores chain state from existing logs
   * 4. Optionally verifies chain integrity on startup
   *
   * @param options - Configuration options
   * @returns Initialized AuditLogger
   * @throws Error if initialization fails
   */
  static async create(options) {
    const hmacKey = await options.hmacKeyProvider.getKey();
    if (!isValidHmacKey(hmacKey)) {
      throw new Error("Invalid HMAC key: must be 32 bytes (256 bits)");
    }
    const config = {
      ...DEFAULT_AUDIT_LOGGER_CONFIG,
      ...options.config
    };
    const logger = new _AuditLogger(hmacKey, config);
    await logger.initialize();
    await logger.restoreChainState();
    if (config.verifyOnStartup) {
      const result = await logger.verifyChain({
        recentEntries: config.startupVerificationEntries
      });
      if (!result.valid) {
        logger.emit("tamper_detected", result);
        if (options.onTamperDetected) {
          await options.onTamperDetected(result);
        }
      }
    }
    return logger;
  }
  /**
   * Initialize the audit log storage
   */
  async initialize() {
    await fs.mkdir(this.logDir, { recursive: true, mode: DIR_MODE });
    try {
      await fs.access(this.currentLogPath);
    } catch {
      await fs.writeFile(this.currentLogPath, "", { mode: LOG_FILE_MODE });
    }
    this.isInitialized = true;
  }
  /**
   * Restore chain state from existing log files
   */
  async restoreChainState() {
    const lastEntry = await this.getLastEntry();
    if (lastEntry) {
      this.chain.setState({
        sequence: lastEntry.seq,
        previousHash: lastEntry.hash
      });
    }
  }
  /**
   * Get the log file path for a given date
   */
  getLogFilePath(date) {
    const dateStr = date.toISOString().split("T")[0];
    return path2.join(this.logDir, `${LOG_FILE_PREFIX}${dateStr}${LOG_FILE_EXTENSION}`);
  }
  /**
   * Get the last entry from the current log file
   */
  async getLastEntry() {
    try {
      const content = await fs.readFile(this.currentLogPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      if (lines.length === 0) {
        return null;
      }
      const lastLine = lines[lines.length - 1];
      return JSON.parse(lastLine);
    } catch {
      return null;
    }
  }
  /**
   * Log an audit event
   *
   * @param input - Event data
   * @returns Complete log entry with integrity fields
   * @throws Error if logging fails
   */
  async log(input) {
    if (!this.isInitialized) {
      throw new Error("AuditLogger not initialized. Use AuditLogger.create()");
    }
    const validated = AuditLogInputSchema.parse(input);
    const sanitizedContext = validated.context ? sanitizeForLogging(validated.context) : void 0;
    const writePromise = this.writeLock.then(async () => {
      const today = /* @__PURE__ */ new Date();
      const newLogPath = this.getLogFilePath(today);
      if (newLogPath !== this.currentLogPath) {
        this.currentLogPath = newLogPath;
        try {
          await fs.access(this.currentLogPath);
        } catch {
          await fs.writeFile(this.currentLogPath, "", { mode: LOG_FILE_MODE });
        }
      }
      const entryData = {
        event: validated.event,
        wallet_id: validated.wallet_id,
        wallet_address: validated.wallet_address,
        transaction_type: validated.transaction_type,
        amount_xrp: validated.amount_xrp,
        destination: validated.destination,
        tier: validated.tier,
        policy_decision: validated.policy_decision,
        tx_hash: validated.tx_hash,
        context: sanitizedContext
      };
      const chainEntry = this.chain.createEntry(entryData);
      const entry = {
        seq: chainEntry.sequence,
        timestamp: chainEntry.timestamp,
        event: chainEntry.event,
        wallet_id: chainEntry.wallet_id,
        wallet_address: chainEntry.wallet_address,
        transaction_type: chainEntry.transaction_type,
        amount_xrp: chainEntry.amount_xrp,
        destination: chainEntry.destination,
        tier: chainEntry.tier,
        policy_decision: chainEntry.policy_decision,
        tx_hash: chainEntry.tx_hash,
        context: chainEntry.context,
        prev_hash: chainEntry.previousHash,
        hash: chainEntry.hash
      };
      const line = JSON.stringify(entry) + "\n";
      if (this.config.syncWrites) {
        const handle = await fs.open(this.currentLogPath, "a");
        try {
          await handle.write(line);
          await handle.sync();
        } finally {
          await handle.close();
        }
      } else {
        await fs.appendFile(this.currentLogPath, line);
      }
      this.emit("entry_logged", { seq: entry.seq, event: entry.event });
      return entry;
    });
    this.writeLock = writePromise.then(() => {
    });
    return writePromise;
  }
  /**
   * Verify hash chain integrity
   *
   * @param options - Verification options
   * @returns Verification result with any detected errors
   */
  async verifyChain(options = {}) {
    const entries = await this.loadEntries(options);
    if (entries.length === 0) {
      return {
        valid: true,
        entriesVerified: 0,
        startSequence: 0,
        endSequence: 0,
        durationMs: 0,
        errors: []
      };
    }
    const hashableEntries = entries.map((e) => ({
      sequence: e.seq,
      timestamp: e.timestamp,
      previousHash: e.prev_hash,
      hash: e.hash,
      event: e.event,
      wallet_id: e.wallet_id,
      wallet_address: e.wallet_address,
      transaction_type: e.transaction_type,
      amount_xrp: e.amount_xrp,
      destination: e.destination,
      tier: e.tier,
      policy_decision: e.policy_decision,
      tx_hash: e.tx_hash,
      context: e.context
    }));
    const result = this.chain.verifyEntries(hashableEntries, options);
    if (!result.valid) {
      this.emit("tamper_detected", result);
    }
    return result;
  }
  /**
   * Load entries for verification/querying
   */
  async loadEntries(options = {}) {
    const entries = [];
    try {
      const content = await fs.readFile(this.currentLogPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          entries.push(entry);
        } catch {
          continue;
        }
      }
    } catch {
      return [];
    }
    let result = entries;
    if (options.startSequence !== void 0 || options.endSequence !== void 0) {
      result = result.filter((e) => {
        if (options.startSequence !== void 0 && e.seq < options.startSequence) {
          return false;
        }
        if (options.endSequence !== void 0 && e.seq > options.endSequence) {
          return false;
        }
        return true;
      });
    }
    if (options.recentEntries !== void 0) {
      result = result.slice(-options.recentEntries);
    }
    return result;
  }
  /**
   * Query logs by criteria
   *
   * @param query - Query parameters
   * @returns Matching log entries
   */
  async query(query) {
    const allEntries = await this.loadEntries({});
    let filtered = allEntries;
    if (query.startDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) >= query.startDate);
    }
    if (query.endDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) <= query.endDate);
    }
    if (query.eventTypes && query.eventTypes.length > 0) {
      const eventSet = new Set(query.eventTypes);
      filtered = filtered.filter((e) => eventSet.has(e.event));
    }
    if (query.walletId) {
      filtered = filtered.filter((e) => e.wallet_id === query.walletId);
    }
    if (query.walletAddress) {
      filtered = filtered.filter((e) => e.wallet_address === query.walletAddress);
    }
    if (query.txHash) {
      filtered = filtered.filter((e) => e.tx_hash === query.txHash);
    }
    if (query.sortOrder === "desc") {
      filtered = filtered.reverse();
    }
    if (query.limit && query.limit > 0) {
      filtered = filtered.slice(0, query.limit);
    }
    return filtered;
  }
  /**
   * Get current chain state
   *
   * @returns Current sequence number and previous hash
   */
  getChainState() {
    return this.chain.getState();
  }
  /**
   * Get storage statistics
   *
   * @returns Storage statistics
   */
  async getStats() {
    const entries = await this.loadEntries({});
    let fileSize = 0;
    try {
      const stat2 = await fs.stat(this.currentLogPath);
      fileSize = stat2.size;
    } catch {
    }
    const stats = {
      totalEntries: entries.length,
      currentFileSize: fileSize,
      currentFilePath: this.currentLogPath
    };
    if (entries.length > 0) {
      const firstEntry = entries[0];
      const lastEntry = entries[entries.length - 1];
      stats.oldestEntry = firstEntry.timestamp;
      stats.newestEntry = lastEntry.timestamp;
    }
    return stats;
  }
  /**
   * Graceful shutdown
   *
   * Ensures all pending writes complete and disposes of the hash chain.
   *
   * @param timeout - Maximum wait time for pending writes (ms)
   */
  async shutdown(timeout = 5e3) {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Shutdown timeout")), timeout);
    });
    try {
      await Promise.race([this.writeLock, timeoutPromise]);
    } catch {
    }
    this.chain.dispose();
    this.emit("shutdown");
  }
};
function createMemoryKeyProvider(key) {
  return {
    getKey: async () => key
  };
}
function getDefaultAuditDir(network) {
  const baseDir = path2.join(process.env["HOME"] || "~", DEFAULT_BASE_DIR);
  return path2.join(baseDir, network, AUDIT_SUBDIR);
}
function tierToNumeric(tier) {
  const map = {
    autonomous: 1,
    delayed: 2,
    cosign: 3,
    prohibited: 4
  };
  return map[tier];
}
function numericToTier(tier) {
  const map = {
    1: "autonomous",
    2: "delayed",
    3: "cosign",
    4: "prohibited"
  };
  return map[tier];
}
var PolicyError = class extends Error {
  constructor(message, code, recoverable = false) {
    super(message);
    this.code = code;
    this.recoverable = recoverable;
    this.name = "PolicyError";
  }
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      recoverable: this.recoverable
    };
  }
};
var PolicyLoadError = class extends PolicyError {
  constructor(message) {
    super(message, "POLICY_LOAD_ERROR", false);
    this.name = "PolicyLoadError";
  }
};
var PolicyValidationError = class extends PolicyError {
  constructor(message, issues) {
    super(message, "POLICY_VALIDATION_ERROR", false);
    this.issues = issues;
    this.name = "PolicyValidationError";
  }
};
var PolicyEvaluationError = class extends PolicyError {
  constructor(message) {
    super(message, "POLICY_EVALUATION_ERROR", true);
    this.name = "PolicyEvaluationError";
  }
};
var PolicyIntegrityError = class extends PolicyError {
  constructor() {
    super("Policy integrity verification failed", "POLICY_INTEGRITY_ERROR", false);
    this.name = "PolicyIntegrityError";
  }
};
var LimitExceededError = class extends PolicyError {
  constructor(message, limitType, currentValue, limitValue) {
    super(message, "LIMIT_EXCEEDED", true);
    this.limitType = limitType;
    this.currentValue = currentValue;
    this.limitValue = limitValue;
    this.name = "LimitExceededError";
  }
};

// src/policy/evaluator.ts
var TRANSACTION_CATEGORIES = {
  // Payments
  Payment: "payments",
  // Trustlines
  TrustSet: "trustlines",
  // DEX
  OfferCreate: "dex",
  OfferCancel: "dex",
  // Escrow
  EscrowCreate: "escrow",
  EscrowFinish: "escrow",
  EscrowCancel: "escrow",
  // Payment Channels
  PaymentChannelCreate: "paychan",
  PaymentChannelFund: "paychan",
  PaymentChannelClaim: "paychan",
  // Account
  AccountSet: "account",
  AccountDelete: "account",
  SetRegularKey: "account",
  SignerListSet: "account",
  DepositPreauth: "account",
  // NFT
  NFTokenMint: "nft",
  NFTokenBurn: "nft",
  NFTokenCreateOffer: "nft",
  NFTokenCancelOffer: "nft",
  NFTokenAcceptOffer: "nft",
  // AMM
  AMMCreate: "amm",
  AMMDeposit: "amm",
  AMMWithdraw: "amm",
  AMMVote: "amm",
  AMMBid: "amm",
  AMMDelete: "amm",
  // Checks
  CheckCreate: "checks",
  CheckCash: "checks",
  CheckCancel: "checks",
  // Tickets
  TicketCreate: "tickets",
  // Clawback
  Clawback: "clawback",
  // DID
  DIDSet: "did",
  DIDDelete: "did",
  // Cross-chain
  XChainAccountCreateCommit: "xchain",
  XChainAddClaimAttestation: "xchain",
  XChainClaim: "xchain",
  XChainCommit: "xchain",
  XChainCreateBridge: "xchain",
  XChainCreateClaimID: "xchain",
  XChainModifyBridge: "xchain"
};
function getTransactionCategory(type) {
  return TRANSACTION_CATEGORIES[type] ?? "unknown";
}
var RuleEvaluator = class {
  compiledRules = /* @__PURE__ */ new Map();
  regexCache = /* @__PURE__ */ new Map();
  options;
  constructor(options) {
    this.options = {
      regexTimeoutMs: options?.regexTimeoutMs ?? 100,
      maxRegexInputLength: options?.maxRegexInputLength ?? 1e4
    };
  }
  /**
   * Compile rules for efficient evaluation.
   * Rules are sorted by priority (lower = higher priority).
   */
  compileRules(rules) {
    this.compiledRules.clear();
    const enabledRules = rules.filter((rule) => rule.enabled !== false).sort((a, b) => a.priority - b.priority);
    for (const rule of enabledRules) {
      const compiled = this.compileRule(rule);
      this.compiledRules.set(rule.id, compiled);
    }
  }
  /**
   * Compile a single rule.
   */
  compileRule(rule) {
    return {
      id: rule.id,
      name: rule.name,
      priority: rule.priority,
      evaluator: this.compileCondition(rule.condition),
      action: rule.action
    };
  }
  /**
   * Compile a condition into an evaluator function.
   */
  compileCondition(condition) {
    if (this.isAlwaysCondition(condition)) {
      return () => true;
    }
    if (this.isAndCondition(condition)) {
      const subEvaluators = condition.and.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.every((evaluator) => evaluator(ctx, policy));
    }
    if (this.isOrCondition(condition)) {
      const subEvaluators = condition.or.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.some((evaluator) => evaluator(ctx, policy));
    }
    if (this.isNotCondition(condition)) {
      const subEvaluator = this.compileCondition(condition.not);
      return (ctx, policy) => !subEvaluator(ctx, policy);
    }
    if (this.isFieldCondition(condition)) {
      return this.compileFieldCondition(condition);
    }
    throw new PolicyEvaluationError(
      `Unknown condition type: ${JSON.stringify(condition)}`
    );
  }
  /**
   * Compile a field condition.
   */
  compileFieldCondition(condition) {
    const { field, operator, value } = condition;
    return (context, policy) => {
      const fieldValue = this.extractFieldValue(field, context, policy);
      const compareValue = this.resolveValue(value, policy);
      return this.evaluateOperator(operator, fieldValue, compareValue);
    };
  }
  /**
   * Extract a field value from the policy context.
   */
  extractFieldValue(field, context, policy) {
    switch (field) {
      // Transaction fields
      case "destination":
        return context.transaction.destination;
      case "amount_xrp":
        return context.transaction.amount_xrp ?? 0;
      case "amount_drops":
        return context.transaction.amount_drops ?? 0n;
      case "transaction_type":
        return context.transaction.type;
      case "transaction_category":
        return getTransactionCategory(context.transaction.type);
      case "memo":
        return context.transaction.memo ?? "";
      case "memo_type":
        return context.transaction.memo_type ?? "";
      case "fee_drops":
        return context.transaction.fee_drops ?? 0;
      case "destination_tag":
        return context.transaction.destination_tag;
      case "source_tag":
        return context.transaction.source_tag;
      case "currency":
        return context.transaction.currency;
      case "issuer":
        return context.transaction.issuer;
      // Wallet fields
      case "wallet_address":
        return context.wallet.address;
      case "network":
        return context.wallet.network;
      // Derived fields
      case "is_new_destination":
        if (!context.transaction.destination) return false;
        const allowlist = policy.allowlist?.addresses ?? [];
        return !allowlist.includes(context.transaction.destination);
      default:
        throw new PolicyEvaluationError(`Unknown field: ${field}`);
    }
  }
  /**
   * Resolve a value (may be a reference to policy lists).
   */
  resolveValue(value, policy) {
    if (this.isValueReference(value)) {
      return this.resolveReference(value.ref, policy);
    }
    return value;
  }
  /**
   * Resolve a reference to a policy list.
   */
  resolveReference(ref, policy) {
    switch (ref) {
      case "blocklist.addresses":
        return policy.blocklist?.addresses ?? [];
      case "blocklist.memo_patterns":
        return policy.blocklist?.memo_patterns ?? [];
      case "blocklist.currency_issuers":
        return policy.blocklist?.currency_issuers ?? [];
      case "allowlist.addresses":
        return policy.allowlist?.addresses ?? [];
      case "allowlist.trusted_tags":
        return policy.allowlist?.trusted_tags ?? [];
      default:
        throw new PolicyEvaluationError(`Unknown reference: ${ref}`);
    }
  }
  /**
   * Evaluate an operator.
   */
  evaluateOperator(operator, fieldValue, compareValue) {
    switch (operator) {
      // Equality operators
      case "==":
        return fieldValue === compareValue;
      case "!=":
        return fieldValue !== compareValue;
      // Numeric comparison operators
      case ">":
        return this.asNumber(fieldValue) > this.asNumber(compareValue);
      case ">=":
        return this.asNumber(fieldValue) >= this.asNumber(compareValue);
      case "<":
        return this.asNumber(fieldValue) < this.asNumber(compareValue);
      case "<=":
        return this.asNumber(fieldValue) <= this.asNumber(compareValue);
      // Array operators
      case "in":
        return this.asArray(compareValue).includes(fieldValue);
      case "not_in":
        return !this.asArray(compareValue).includes(fieldValue);
      // String operators
      case "matches":
        return this.matchesRegex(this.asString(fieldValue), this.asString(compareValue));
      case "contains":
        return this.asString(fieldValue).includes(this.asString(compareValue));
      case "starts_with":
        return this.asString(fieldValue).startsWith(this.asString(compareValue));
      case "ends_with":
        return this.asString(fieldValue).endsWith(this.asString(compareValue));
      // Category operator
      case "in_category":
        return this.isInCategory(this.asString(fieldValue), this.asString(compareValue));
      default:
        throw new PolicyEvaluationError(`Unknown operator: ${operator}`);
    }
  }
  /**
   * Check if a regex pattern is potentially vulnerable to ReDoS.
   *
   * Detects common ReDoS patterns:
   * - Nested quantifiers: (a+)+, (a*)*
   * - Overlapping alternation: (a|a)+
   * - Exponential backtracking patterns
   */
  isReDoSVulnerable(pattern) {
    const dangerousPatterns = [
      /\([^)]*[+*][^)]*\)[+*]/,
      // Nested quantifiers: (a+)+, (.*)*
      /\([^)]*\|[^)]*\)[+*]{2,}/,
      // Alternation with repeated quantifiers
      /\(\.\*\)[+*]/,
      // (.*)+
      /\(\.\+\)[+*]/,
      // (.+)+
      /\[[^\]]*\][+*]{2,}[^\s]*\[[^\]]*\][+*]{2,}/
      // Multiple char classes with quantifiers
    ];
    for (const dangerous of dangerousPatterns) {
      if (dangerous.test(pattern)) {
        return true;
      }
    }
    return false;
  }
  /**
   * Match a value against a regex pattern.
   */
  matchesRegex(value, pattern) {
    let regex = this.regexCache.get(pattern);
    if (!regex) {
      if (this.isReDoSVulnerable(pattern)) {
        throw new PolicyEvaluationError(
          `Regex pattern rejected due to potential ReDoS vulnerability: ${pattern}`
        );
      }
      try {
        regex = new RegExp(pattern, "i");
        this.regexCache.set(pattern, regex);
      } catch (error) {
        throw new PolicyEvaluationError(`Invalid regex pattern: ${pattern}`);
      }
    }
    const truncatedValue = value.length > this.options.maxRegexInputLength ? value.slice(0, this.options.maxRegexInputLength) : value;
    return regex.test(truncatedValue);
  }
  /**
   * Check if a transaction type is in a category.
   */
  isInCategory(txType, category) {
    return getTransactionCategory(txType) === category;
  }
  // ============================================================================
  // TYPE GUARDS
  // ============================================================================
  isAlwaysCondition(condition) {
    return "always" in condition && condition.always === true;
  }
  isAndCondition(condition) {
    return "and" in condition;
  }
  isOrCondition(condition) {
    return "or" in condition;
  }
  isNotCondition(condition) {
    return "not" in condition;
  }
  isFieldCondition(condition) {
    return "field" in condition;
  }
  isValueReference(value) {
    return typeof value === "object" && value !== null && "ref" in value && typeof value.ref === "string";
  }
  // ============================================================================
  // TYPE CONVERSIONS
  // ============================================================================
  asNumber(value) {
    if (typeof value === "number") return value;
    if (typeof value === "bigint") return Number(value);
    if (typeof value === "string") {
      const parsed = parseFloat(value);
      if (isNaN(parsed)) {
        throw new PolicyEvaluationError(`Cannot convert "${value}" to number`);
      }
      return parsed;
    }
    throw new PolicyEvaluationError(`Cannot convert ${typeof value} to number`);
  }
  asString(value) {
    if (typeof value === "string") return value;
    if (value === null || value === void 0) return "";
    return String(value);
  }
  asArray(value) {
    if (Array.isArray(value)) return value;
    throw new PolicyEvaluationError(`Expected array, got ${typeof value}`);
  }
  // ============================================================================
  // PUBLIC EVALUATION METHODS
  // ============================================================================
  /**
   * Evaluate rules against a context.
   * Returns the first matching rule's result.
   */
  evaluate(context, policy) {
    for (const [ruleId, compiled] of this.compiledRules) {
      try {
        const matches = compiled.evaluator(context, policy);
        if (matches) {
          return {
            matched: true,
            ruleId: compiled.id,
            ruleName: compiled.name,
            tier: compiled.action.tier,
            reason: compiled.action.reason ?? `Matched rule: ${compiled.name}`,
            overrideDelaySeconds: compiled.action.override_delay_seconds,
            notify: compiled.action.notify,
            logLevel: compiled.action.log_level
          };
        }
      } catch (error) {
        console.error(`Rule evaluation error for ${ruleId}:`, error);
      }
    }
    return {
      matched: false,
      ruleId: "default-deny",
      ruleName: "No matching rule",
      tier: "prohibited",
      reason: "No matching rule (default deny)"
    };
  }
  /**
   * Get the number of compiled rules.
   */
  getRuleCount() {
    return this.compiledRules.size;
  }
  /**
   * Clear compiled rules and caches.
   */
  clear() {
    this.compiledRules.clear();
    this.regexCache.clear();
  }
};
function checkBlocklist(context, policy, regexCache) {
  const blocklist = policy.blocklist;
  if (!blocklist) {
    return { blocked: false };
  }
  if (context.transaction.destination && blocklist.addresses?.includes(context.transaction.destination)) {
    return {
      blocked: true,
      reason: "Destination address is blocklisted",
      matchedRule: "blocklist-address"
    };
  }
  if (context.transaction.issuer && blocklist.currency_issuers?.includes(context.transaction.issuer)) {
    return {
      blocked: true,
      reason: "Token issuer is blocklisted",
      matchedRule: "blocklist-issuer"
    };
  }
  if (context.transaction.memo && blocklist.memo_patterns?.length) {
    const cache = regexCache ?? /* @__PURE__ */ new Map();
    for (const pattern of blocklist.memo_patterns) {
      let regex = cache.get(pattern);
      if (!regex) {
        try {
          regex = new RegExp(pattern, "i");
          cache.set(pattern, regex);
        } catch {
          continue;
        }
      }
      const memo = context.transaction.memo.length > 1e4 ? context.transaction.memo.slice(0, 1e4) : context.transaction.memo;
      if (regex.test(memo)) {
        return {
          blocked: true,
          reason: "Memo contains blocked pattern (potential injection)",
          matchedRule: "blocklist-memo-pattern",
          injectionDetected: true
        };
      }
    }
  }
  return { blocked: false };
}
function isInAllowlist(context, policy) {
  const allowlist = policy.allowlist;
  if (!allowlist) return false;
  if (context.transaction.destination && allowlist.addresses?.includes(context.transaction.destination)) {
    return true;
  }
  if (context.transaction.destination && allowlist.exchange_addresses) {
    const exchange = allowlist.exchange_addresses.find(
      (ex) => ex.address === context.transaction.destination
    );
    if (exchange) {
      if (exchange.require_tag && !context.transaction.destination_tag) {
        return false;
      }
      return true;
    }
  }
  if (context.transaction.destination_tag !== void 0 && allowlist.trusted_tags?.includes(context.transaction.destination_tag)) {
    return true;
  }
  return false;
}

// src/policy/limits.ts
var LimitTracker = class {
  state;
  config;
  persistencePath;
  clock;
  resetInterval;
  constructor(options) {
    this.config = options.config;
    this.persistencePath = options.persistencePath;
    this.clock = options.clock ?? (() => /* @__PURE__ */ new Date());
    this.state = this.createFreshState();
    this.schedulePeriodicCheck();
  }
  /**
   * Create fresh limit state.
   */
  createFreshState() {
    const now = this.clock();
    return {
      daily: {
        date: this.getDateString(now),
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: /* @__PURE__ */ new Set(),
        lastTransactionTime: null
      },
      hourly: {
        transactions: []
      },
      cooldown: {
        active: false,
        reason: null,
        expiresAt: null,
        triggeredBy: null
      }
    };
  }
  /**
   * Check if a transaction would exceed any limits.
   * Does NOT record the transaction - call recordTransaction after successful signing.
   */
  checkLimits(context) {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    if (this.state.cooldown.active) {
      if (this.state.cooldown.expiresAt && now < this.state.cooldown.expiresAt) {
        return {
          exceeded: true,
          reason: `Cooldown active: ${this.state.cooldown.reason}`,
          limitType: "cooldown",
          currentValue: 0,
          limitValue: 0,
          expiresAt: this.state.cooldown.expiresAt
        };
      } else {
        this.clearCooldown();
      }
    }
    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    if (this.config.maxAmountPerTxXrp !== void 0 && txAmountXrp > this.config.maxAmountPerTxXrp) {
      return {
        exceeded: true,
        reason: `Transaction amount ${txAmountXrp} XRP exceeds per-tx limit of ${this.config.maxAmountPerTxXrp} XRP`,
        limitType: "per_tx_amount",
        currentValue: txAmountXrp,
        limitValue: this.config.maxAmountPerTxXrp
      };
    }
    if (this.state.daily.transactionCount >= this.config.maxTransactionsPerDay) {
      return {
        exceeded: true,
        reason: `Daily transaction count limit (${this.config.maxTransactionsPerDay}) exceeded`,
        limitType: "daily_count",
        currentValue: this.state.daily.transactionCount,
        limitValue: this.config.maxTransactionsPerDay
      };
    }
    const hourlyCount = this.state.hourly.transactions.length;
    if (hourlyCount >= this.config.maxTransactionsPerHour) {
      return {
        exceeded: true,
        reason: `Hourly transaction count limit (${this.config.maxTransactionsPerHour}) exceeded`,
        limitType: "hourly_count",
        currentValue: hourlyCount,
        limitValue: this.config.maxTransactionsPerHour
      };
    }
    const projectedVolume = this.state.daily.totalVolumeXrp + txAmountXrp;
    if (projectedVolume > this.config.maxTotalVolumeXrpPerDay) {
      return {
        exceeded: true,
        reason: `Daily XRP volume limit (${this.config.maxTotalVolumeXrpPerDay} XRP) would be exceeded`,
        limitType: "daily_volume",
        currentValue: this.state.daily.totalVolumeXrp,
        limitValue: this.config.maxTotalVolumeXrpPerDay,
        requestedAmount: txAmountXrp
      };
    }
    const destination = context.transaction.destination;
    if (this.config.maxUniqueDestinationsPerDay !== void 0 && destination && !this.state.daily.uniqueDestinations.has(destination) && this.state.daily.uniqueDestinations.size >= this.config.maxUniqueDestinationsPerDay) {
      return {
        exceeded: true,
        reason: `Daily unique destination limit (${this.config.maxUniqueDestinationsPerDay}) exceeded`,
        limitType: "unique_destinations",
        currentValue: this.state.daily.uniqueDestinations.size,
        limitValue: this.config.maxUniqueDestinationsPerDay
      };
    }
    return { exceeded: false };
  }
  /**
   * Record a successfully signed transaction.
   * Call this AFTER signing succeeds, not before.
   */
  recordTransaction(context) {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    const destination = context.transaction.destination;
    this.state.daily.transactionCount++;
    this.state.daily.totalVolumeXrp += txAmountXrp;
    this.state.daily.lastTransactionTime = now;
    if (destination) {
      this.state.daily.uniqueDestinations.add(destination);
    }
    this.state.hourly.transactions.push({
      timestamp: now,
      amountXrp: txAmountXrp,
      destination: destination ?? ""
    });
    const cooldownConfig = this.config.cooldownAfterHighValue;
    if (cooldownConfig?.enabled && txAmountXrp >= cooldownConfig.thresholdXrp) {
      this.activateCooldown(
        `High-value transaction (${txAmountXrp} XRP)`,
        cooldownConfig.cooldownSeconds,
        context.transaction.type
      );
    }
  }
  /**
   * Check if daily reset should happen.
   */
  maybeResetDaily(now) {
    const currentDate = this.getDateString(now);
    const currentHour = now.getUTCHours();
    const shouldReset = this.state.daily.date !== currentDate || this.state.daily.date === currentDate && currentHour >= this.config.dailyResetHour && this.state.daily.lastTransactionTime && this.state.daily.lastTransactionTime.getUTCHours() < this.config.dailyResetHour;
    if (shouldReset) {
      this.state.daily = {
        date: currentDate,
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: /* @__PURE__ */ new Set(),
        lastTransactionTime: null
      };
    }
  }
  /**
   * Remove transactions older than 1 hour from sliding window.
   */
  pruneHourlyWindow(now) {
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1e3);
    this.state.hourly.transactions = this.state.hourly.transactions.filter(
      (tx) => tx.timestamp > oneHourAgo
    );
  }
  /**
   * Activate cooldown period.
   */
  activateCooldown(reason, durationSeconds, triggeredBy) {
    const now = this.clock();
    this.state.cooldown = {
      active: true,
      reason,
      expiresAt: new Date(now.getTime() + durationSeconds * 1e3),
      triggeredBy
    };
  }
  /**
   * Clear active cooldown.
   */
  clearCooldown() {
    this.state.cooldown = {
      active: false,
      reason: null,
      expiresAt: null,
      triggeredBy: null
    };
  }
  /**
   * Schedule periodic check for daily reset.
   */
  schedulePeriodicCheck() {
    this.resetInterval = setInterval(() => {
      this.maybeResetDaily(this.clock());
    }, 60 * 1e3);
  }
  /** Track disposal state */
  isDisposed = false;
  /**
   * Stop periodic checks (for cleanup).
   */
  dispose() {
    if (this.isDisposed) {
      return;
    }
    if (this.resetInterval) {
      clearInterval(this.resetInterval);
      this.resetInterval = void 0;
    }
    this.isDisposed = true;
  }
  /**
   * Check if the tracker has been disposed.
   */
  get disposed() {
    return this.isDisposed;
  }
  // ============================================================================
  // GETTERS FOR RULE EVALUATION
  // ============================================================================
  /**
   * Get current daily XRP volume.
   */
  getDailyVolumeXrp() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.totalVolumeXrp;
  }
  /**
   * Get transactions in the last hour.
   */
  getHourlyCount() {
    const now = this.clock();
    this.pruneHourlyWindow(now);
    return this.state.hourly.transactions.length;
  }
  /**
   * Get daily transaction count.
   */
  getDailyCount() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.transactionCount;
  }
  /**
   * Get unique destination count for today.
   */
  getUniqueDestinationCount() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.size;
  }
  /**
   * Check if a destination has been used before today.
   */
  isDestinationKnown(destination) {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.has(destination);
  }
  /**
   * Get complete limit state (copy for safety).
   */
  getState() {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    return {
      daily: {
        ...this.state.daily,
        uniqueDestinations: new Set(this.state.daily.uniqueDestinations)
      },
      hourly: {
        transactions: [...this.state.hourly.transactions]
      },
      cooldown: { ...this.state.cooldown }
    };
  }
  /**
   * Get remaining limits for current period.
   */
  getRemainingLimits() {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    return {
      dailyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerDay - this.state.daily.transactionCount
      ),
      hourlyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerHour - this.state.hourly.transactions.length
      ),
      dailyVolumeRemainingXrp: Math.max(
        0,
        this.config.maxTotalVolumeXrpPerDay - this.state.daily.totalVolumeXrp
      ),
      uniqueDestinationsRemaining: Math.max(
        0,
        (this.config.maxUniqueDestinationsPerDay ?? Infinity) - this.state.daily.uniqueDestinations.size
      )
    };
  }
  /**
   * Reset all limits. Requires confirmation string for safety.
   */
  reset(confirmation) {
    if (confirmation !== "CONFIRM_LIMIT_RESET") {
      throw new Error("Invalid confirmation string for limit reset");
    }
    this.state = this.createFreshState();
  }
  /**
   * Get date string in YYYY-MM-DD format.
   */
  getDateString(date) {
    return date.toISOString().split("T")[0];
  }
};
function createLimitTracker(limits, options) {
  const dropsToXrp3 = (drops) => {
    return Number(BigInt(drops)) / 1e6;
  };
  const config = {
    dailyResetHour: options?.dailyResetHour ?? 0,
    maxTransactionsPerHour: limits.max_tx_per_hour,
    maxTransactionsPerDay: limits.max_tx_per_day,
    maxTotalVolumeXrpPerDay: dropsToXrp3(limits.max_daily_volume_drops),
    maxAmountPerTxXrp: dropsToXrp3(limits.max_amount_per_tx_drops),
    maxUniqueDestinationsPerDay: options?.maxUniqueDestinationsPerDay,
    cooldownAfterHighValue: options?.cooldownAfterHighValue
  };
  const trackerOptions = {
    config
  };
  if (options?.clock) {
    trackerOptions.clock = options.clock;
  }
  return new LimitTracker(trackerOptions);
}

// src/policy/engine.ts
var PolicyEngine = class {
  /** Frozen policy data */
  policy;
  /** SHA-256 hash of serialized policy */
  policyHash;
  /** When policy was loaded */
  loadedAt;
  /** Rule evaluator */
  ruleEvaluator;
  /** Limit tracker */
  limitTracker;
  /** Custom clock for testing */
  clock;
  /** Regex cache for blocklist patterns */
  regexCache = /* @__PURE__ */ new Map();
  constructor(policy, options) {
    this.clock = options?.clock ?? (() => /* @__PURE__ */ new Date());
    this.loadedAt = this.clock();
    this.policyHash = this.computeHash(policy);
    this.policy = this.deepFreeze(policy);
    const evaluatorOptions = {};
    if (options?.regexTimeoutMs !== void 0) {
      evaluatorOptions.regexTimeoutMs = options.regexTimeoutMs;
    }
    this.ruleEvaluator = new RuleEvaluator(evaluatorOptions);
    this.ruleEvaluator.compileRules(this.policy.rules);
    const limitTrackerOptions = {
      config: {
        dailyResetHour: this.policy.limits.daily_reset_utc_hour ?? 0,
        maxTransactionsPerHour: this.policy.limits.max_transactions_per_hour,
        maxTransactionsPerDay: this.policy.limits.max_transactions_per_day,
        maxTotalVolumeXrpPerDay: this.policy.limits.max_total_volume_xrp_per_day,
        maxUniqueDestinationsPerDay: this.policy.limits.max_unique_destinations_per_day,
        cooldownAfterHighValue: this.policy.limits.cooldown_after_high_value ? {
          enabled: this.policy.limits.cooldown_after_high_value.enabled,
          thresholdXrp: this.policy.limits.cooldown_after_high_value.threshold_xrp,
          cooldownSeconds: this.policy.limits.cooldown_after_high_value.cooldown_seconds
        } : void 0
      },
      clock: this.clock
    };
    this.limitTracker = new LimitTracker(limitTrackerOptions);
  }
  /**
   * Evaluate a transaction against the loaded policy.
   */
  evaluate(context) {
    const startTime = performance.now();
    try {
      if (!this.verifyIntegrity()) {
        return this.createProhibitedResult(
          "Policy integrity check failed",
          "integrity-check",
          startTime
        );
      }
      if (this.policy.enabled === false) {
        return this.createProhibitedResult(
          "Policy is disabled",
          "policy-disabled",
          startTime
        );
      }
      const limitResult = this.checkGlobalLimits(context);
      if (limitResult) {
        return {
          ...limitResult,
          evaluationTimeMs: performance.now() - startTime
        };
      }
      const blocklistResult = checkBlocklist(context, this.policy, this.regexCache);
      if (blocklistResult.blocked) {
        return this.createProhibitedResult(
          blocklistResult.reason,
          blocklistResult.matchedRule,
          startTime,
          blocklistResult.injectionDetected
        );
      }
      const typeResult = this.checkTransactionType(context);
      if (typeResult) {
        return {
          ...typeResult,
          evaluationTimeMs: performance.now() - startTime
        };
      }
      const ruleResult = this.ruleEvaluator.evaluate(context, this.policy);
      const finalResult = this.applyTierConstraints(ruleResult, context);
      return {
        ...finalResult,
        evaluationTimeMs: performance.now() - startTime
      };
    } catch (error) {
      console.error("Policy evaluation error:", {
        correlationId: context.correlationId,
        errorType: error instanceof Error ? error.name : "Unknown",
        errorMessage: error instanceof Error ? error.message : String(error),
        transactionType: context.transaction.type
        // Never log amounts, addresses, or other transaction details
      });
      if (error instanceof PolicyError) {
        return this.createProhibitedResult(
          `Policy error: ${error.code}`,
          "error-handler",
          startTime
        );
      }
      return this.createProhibitedResult(
        "Internal policy engine error",
        "error-handler",
        startTime
      );
    }
  }
  /**
   * Check global limits.
   */
  checkGlobalLimits(context) {
    const limitCheck = this.limitTracker.checkLimits(context);
    if (limitCheck.exceeded) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: limitCheck.reason,
        matchedRule: `limit-${limitCheck.limitType}`,
        factors: [
          {
            source: "limit_exceeded",
            tier: "prohibited",
            reason: limitCheck.reason
          }
        ]
      };
    }
    return null;
  }
  /**
   * Check transaction type restrictions.
   */
  checkTransactionType(context) {
    const txType = context.transaction.type;
    const prohibitedTypes = this.policy.tiers.prohibited?.prohibited_transaction_types ?? [];
    if (prohibitedTypes.includes(txType)) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: `Transaction type ${txType} is prohibited`,
        matchedRule: "prohibited-type",
        factors: [
          {
            source: "prohibited_type",
            tier: "prohibited",
            reason: `Transaction type ${txType} is prohibited`
          }
        ]
      };
    }
    const typeConfig = this.policy.transaction_types?.[txType];
    if (typeConfig?.enabled === false) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: `Transaction type ${txType} is disabled`,
        matchedRule: "type-disabled",
        factors: [
          {
            source: "transaction_type",
            tier: "prohibited",
            reason: `Transaction type ${txType} is disabled`
          }
        ]
      };
    }
    return null;
  }
  /**
   * Apply tier-specific constraints and amount escalation.
   */
  applyTierConstraints(ruleResult, context) {
    let tier = ruleResult.tier;
    const factors = [
      {
        source: "rule",
        tier: ruleResult.tier,
        reason: ruleResult.reason
      }
    ];
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.require_cosign && tier !== "prohibited") {
      tier = this.compareTiers("cosign", tier);
      if (tier === "cosign") {
        factors.push({
          source: "transaction_type",
          tier: "cosign",
          reason: `Type ${context.transaction.type} requires co-sign`
        });
      }
    }
    tier = this.applyAmountEscalation(tier, context, factors);
    tier = this.applyNewDestinationEscalation(tier, context, factors);
    const result = {
      allowed: tier !== "prohibited",
      tier,
      tierNumeric: tierToNumeric(tier),
      reason: factors.find((f) => f.tier === tier)?.reason ?? ruleResult.reason,
      matchedRule: ruleResult.ruleId,
      factors
    };
    switch (tier) {
      case "delayed":
        result.delaySeconds = ruleResult.overrideDelaySeconds ?? this.policy.tiers.delayed?.delay_seconds ?? 300;
        result.vetoEnabled = this.policy.tiers.delayed?.veto_enabled ?? true;
        result.notify = ruleResult.notify ?? this.policy.tiers.delayed?.notify_on_queue ?? true;
        break;
      case "cosign":
        result.signerQuorum = this.policy.tiers.cosign?.signer_quorum ?? 2;
        result.approvalTimeoutHours = this.policy.tiers.cosign?.approval_timeout_hours ?? 24;
        result.signerAddresses = this.policy.tiers.cosign?.signer_addresses ?? [];
        result.notify = ruleResult.notify ?? true;
        break;
      case "autonomous":
        result.notify = ruleResult.notify ?? false;
        break;
    }
    return result;
  }
  /**
   * Apply amount-based tier escalation.
   */
  applyAmountEscalation(currentTier, context, factors) {
    const amountXrp = context.transaction.amount_xrp ?? 0;
    const tiers = this.policy.tiers;
    if (tiers.delayed?.max_amount_xrp !== void 0 && amountXrp > tiers.delayed.max_amount_xrp) {
      if (currentTier === "autonomous" || currentTier === "delayed") {
        factors.push({
          source: "amount_limit",
          tier: "cosign",
          reason: `Amount ${amountXrp} XRP exceeds delayed tier max (${tiers.delayed.max_amount_xrp})`
        });
        return "cosign";
      }
    }
    if (tiers.autonomous?.max_amount_xrp !== void 0 && amountXrp > tiers.autonomous.max_amount_xrp) {
      if (currentTier === "autonomous") {
        if (tiers.delayed?.max_amount_xrp === void 0 || amountXrp <= tiers.delayed.max_amount_xrp) {
          factors.push({
            source: "amount_limit",
            tier: "delayed",
            reason: `Amount ${amountXrp} XRP exceeds autonomous tier max (${tiers.autonomous.max_amount_xrp})`
          });
          return "delayed";
        }
      }
    }
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.max_amount_xrp !== void 0 && amountXrp > typeConfig.max_amount_xrp) {
      if (currentTier === "autonomous") {
        factors.push({
          source: "amount_limit",
          tier: "delayed",
          reason: `Amount ${amountXrp} XRP exceeds ${context.transaction.type} limit (${typeConfig.max_amount_xrp})`
        });
        return "delayed";
      }
    }
    return currentTier;
  }
  /**
   * Apply new destination escalation.
   */
  applyNewDestinationEscalation(currentTier, context, factors) {
    if (!context.transaction.destination || currentTier === "prohibited") {
      return currentTier;
    }
    if (isInAllowlist(context, this.policy)) {
      return currentTier;
    }
    let resultTier = currentTier;
    if (resultTier === "autonomous" && this.policy.tiers.autonomous?.require_known_destination) {
      factors.push({
        source: "new_destination",
        tier: "delayed",
        reason: "Destination not in allowlist (require_known_destination enabled)"
      });
      resultTier = "delayed";
    }
    if (this.policy.tiers.cosign?.new_destination_always) {
      const isKnown = this.limitTracker.isDestinationKnown(
        context.transaction.destination
      );
      if (!isKnown) {
        const newTier = this.compareTiers("cosign", resultTier);
        if (newTier === "cosign" && resultTier !== "cosign") {
          factors.push({
            source: "new_destination",
            tier: "cosign",
            reason: "First transaction to new destination"
          });
          resultTier = "cosign";
        }
      }
    }
    return resultTier;
  }
  /**
   * Compare two tiers and return the more restrictive one.
   */
  compareTiers(tier1, tier2) {
    const tierOrder = {
      autonomous: 1,
      delayed: 2,
      cosign: 3,
      prohibited: 4
    };
    return tierOrder[tier1] > tierOrder[tier2] ? tier1 : tier2;
  }
  /**
   * Create a prohibited result.
   */
  createProhibitedResult(reason, matchedRule, startTime, injectionDetected) {
    const result = {
      allowed: false,
      tier: "prohibited",
      tierNumeric: 4,
      reason,
      matchedRule,
      evaluationTimeMs: performance.now() - startTime
    };
    if (injectionDetected !== void 0) {
      result.injectionDetected = injectionDetected;
    }
    return result;
  }
  // ============================================================================
  // PUBLIC METHODS
  // ============================================================================
  /**
   * Get policy hash.
   */
  getPolicyHash() {
    return this.policyHash;
  }
  /**
   * Get policy info.
   */
  getPolicyInfo() {
    const info = {
      name: this.policy.name,
      version: this.policy.version,
      network: this.policy.network,
      enabled: this.policy.enabled,
      loadedAt: this.loadedAt,
      hash: this.policyHash.slice(0, 16),
      ruleCount: this.policy.rules.length,
      enabledRuleCount: this.ruleEvaluator.getRuleCount()
    };
    if (this.policy.description !== void 0) {
      info.description = this.policy.description;
    }
    return info;
  }
  /**
   * Verify policy integrity.
   */
  verifyIntegrity() {
    const currentHash = this.computeHash(this.policy);
    return currentHash === this.policyHash;
  }
  /**
   * Get limit state.
   */
  getLimitState() {
    return this.limitTracker.getState();
  }
  /**
   * Reset limits.
   */
  resetLimits(confirmation) {
    this.limitTracker.reset(confirmation);
  }
  /**
   * Record a successful transaction.
   */
  recordTransaction(context) {
    this.limitTracker.recordTransaction(context);
  }
  /**
   * Dispose of resources.
   */
  dispose() {
    this.limitTracker.dispose();
  }
  /**
   * Simplified transaction evaluation for MCP tools.
   * Creates a PolicyContext internally from the simple transaction context.
   */
  async evaluateTransaction(policyId, txContext) {
    const policyInfo = this.getPolicyInfo();
    if (policyId !== policyInfo.name && policyId !== policyInfo.hash) {
      console.warn(`Policy ID mismatch: expected ${policyInfo.name}, got ${policyId}`);
    }
    let amountXrp;
    if (txContext.amount_drops) {
      amountXrp = Number(BigInt(txContext.amount_drops)) / 1e6;
    }
    const transactionCtx = {
      type: txContext.type
    };
    if (txContext.destination !== void 0) {
      transactionCtx.destination = txContext.destination;
    }
    if (amountXrp !== void 0) {
      transactionCtx.amount_xrp = amountXrp;
    }
    if (txContext.memo !== void 0) {
      transactionCtx.memo = txContext.memo;
    }
    const fullContext = {
      transaction: transactionCtx,
      wallet: {
        address: "",
        // Not relevant for policy evaluation
        network: this.policy.network
      },
      timestamp: /* @__PURE__ */ new Date(),
      correlationId: `eval_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
    };
    const result = this.evaluate(fullContext);
    const simpleResult = {
      tier: result.tierNumeric,
      reason: result.reason,
      allowed: result.allowed
    };
    if (result.tier === "prohibited") {
      simpleResult.violations = [result.reason];
      if (result.injectionDetected) {
        simpleResult.violations.push("Potential prompt injection detected in memo");
      }
    }
    if (result.factors && result.factors.length > 1) {
      simpleResult.warnings = result.factors.filter((f) => f.tier !== result.tier).map((f) => f.reason);
    }
    return simpleResult;
  }
  /**
   * Set or update the policy configuration.
   *
   * NOTE: PolicyEngine is IMMUTABLE by design (ADR-003 security requirement).
   * This method throws an error to prevent silent failures.
   *
   * To update a policy, you must:
   * 1. Create a new PolicyEngine instance with the new policy
   * 2. Replace the old engine atomically at the server level
   * 3. Consider requiring human approval for policy changes
   *
   * @throws PolicyLoadError always - policies cannot be changed at runtime
   */
  async setPolicy(policy) {
    throw new PolicyLoadError(
      `Policy updates are not supported at runtime (ADR-003 immutability requirement). Requested policy: ${policy.policy_id} v${policy.policy_version}. To update policies, restart the server with the new policy configuration.`
    );
  }
  // ============================================================================
  // PRIVATE HELPERS
  // ============================================================================
  /**
   * Compute SHA-256 hash of policy.
   */
  computeHash(policy) {
    const content = JSON.stringify(policy);
    return createHash("sha256").update(content).digest("hex");
  }
  /**
   * Deep freeze an object.
   */
  deepFreeze(obj) {
    const propNames = Object.getOwnPropertyNames(obj);
    for (const name of propNames) {
      const value = obj[name];
      if (value && typeof value === "object") {
        this.deepFreeze(value);
      }
    }
    return Object.freeze(obj);
  }
};
function createPolicyEngine(policy, options) {
  const internalPolicy = {
    version: policy.policy_version,
    name: policy.policy_id,
    network: "mainnet",
    // Default, should be provided externally
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: dropsToXrp(policy.limits.max_amount_per_tx_drops),
        daily_limit_xrp: dropsToXrp(policy.limits.max_daily_volume_drops),
        require_known_destination: policy.destinations.mode === "allowlist" || !policy.destinations.allow_new_destinations,
        allowed_transaction_types: policy.transaction_types.allowed
      },
      delayed: {
        max_amount_xrp: dropsToXrp(policy.escalation.amount_threshold_drops),
        delay_seconds: policy.escalation.delay_seconds ?? 300,
        veto_enabled: true,
        notify_on_queue: true
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: policy.escalation.new_destination === 3,
        approval_timeout_hours: 24
      },
      prohibited: {
        prohibited_transaction_types: policy.transaction_types.blocked ?? []
      }
    },
    rules: buildRulesFromPolicy(policy),
    blocklist: {
      addresses: policy.destinations.blocklist ?? []
    },
    allowlist: {
      addresses: policy.destinations.mode === "allowlist" ? policy.destinations.allowlist ?? [] : []
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: policy.limits.max_tx_per_hour,
      max_transactions_per_day: policy.limits.max_tx_per_day,
      max_total_volume_xrp_per_day: dropsToXrp(policy.limits.max_daily_volume_drops)
    }
  };
  return new PolicyEngine(internalPolicy, options);
}
function dropsToXrp(drops) {
  return Number(BigInt(drops)) / 1e6;
}
function buildRulesFromPolicy(policy) {
  const rules = [];
  let priority = 1;
  if (policy.destinations.blocklist && policy.destinations.blocklist.length > 0) {
    rules.push({
      id: "blocklist-check",
      name: "Blocklist Check",
      priority: priority++,
      condition: {
        field: "destination",
        operator: "in",
        value: { ref: "blocklist.addresses" }
      },
      action: {
        tier: "prohibited",
        reason: "Destination is blocklisted"
      }
    });
  }
  if (policy.transaction_types.blocked && policy.transaction_types.blocked.length > 0) {
    for (const txType of policy.transaction_types.blocked) {
      rules.push({
        id: `block-${txType.toLowerCase()}`,
        name: `Block ${txType}`,
        priority: priority++,
        condition: {
          field: "transaction_type",
          operator: "==",
          value: txType
        },
        action: {
          tier: "prohibited",
          reason: `Transaction type ${txType} is not allowed`
        }
      });
    }
  }
  if (policy.transaction_types.require_approval && policy.transaction_types.require_approval.length > 0) {
    for (const txType of policy.transaction_types.require_approval) {
      rules.push({
        id: `require-approval-${txType.toLowerCase()}`,
        name: `Require Approval for ${txType}`,
        priority: priority++,
        condition: {
          field: "transaction_type",
          operator: "==",
          value: txType
        },
        action: {
          tier: "cosign",
          reason: `Transaction type ${txType} requires approval`
        }
      });
    }
  }
  const thresholdXrp = dropsToXrp(policy.escalation.amount_threshold_drops);
  rules.push({
    id: "high-value-cosign",
    name: "High Value Transaction",
    priority: priority++,
    condition: {
      field: "amount_xrp",
      operator: ">=",
      value: thresholdXrp
    },
    action: {
      tier: policy.escalation.new_destination === 3 ? "cosign" : "delayed",
      reason: `Amount exceeds ${thresholdXrp} XRP threshold`
    }
  });
  if (policy.destinations.mode === "allowlist" || !policy.destinations.allow_new_destinations) {
    rules.push({
      id: "new-destination-check",
      name: "New Destination Check",
      priority: priority++,
      condition: {
        not: {
          field: "destination",
          operator: "in",
          value: { ref: "allowlist.addresses" }
        }
      },
      action: {
        tier: policy.destinations.new_destination_tier === 3 ? "cosign" : policy.destinations.new_destination_tier === 2 ? "delayed" : "prohibited",
        reason: "Destination not in allowlist"
      }
    });
  }
  rules.push({
    id: "default-allow",
    name: "Default Allow",
    priority: 999,
    condition: {
      always: true
    },
    action: {
      tier: "autonomous",
      reason: "Transaction within policy limits"
    }
  });
  return rules;
}
function createTestPolicy(network = "testnet", overrides) {
  const basePolicy = {
    version: "1.0",
    name: `${network}-test-policy`,
    description: "Test policy for development",
    network,
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: network === "mainnet" ? 100 : 1e4,
        daily_limit_xrp: network === "mainnet" ? 1e3 : 1e5,
        require_known_destination: network === "mainnet",
        allowed_transaction_types: ["Payment", "EscrowFinish", "EscrowCancel"]
      },
      delayed: {
        max_amount_xrp: network === "mainnet" ? 1e3 : 1e5,
        delay_seconds: network === "mainnet" ? 300 : 60,
        veto_enabled: true,
        notify_on_queue: true
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: network === "mainnet",
        approval_timeout_hours: 24
      },
      prohibited: {
        prohibited_transaction_types: ["Clawback"]
      }
    },
    rules: [
      {
        id: "default-allow",
        name: "Default Allow",
        priority: 999,
        condition: { always: true },
        action: { tier: "autonomous", reason: "Within policy limits" }
      }
    ],
    blocklist: {
      addresses: [],
      memo_patterns: ["ignore.*previous", "\\[INST\\]", "<<SYS>>"]
    },
    allowlist: {
      addresses: []
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: network === "mainnet" ? 50 : 1e3,
      max_transactions_per_day: network === "mainnet" ? 200 : 1e4,
      max_unique_destinations_per_day: network === "mainnet" ? 20 : 500,
      max_total_volume_xrp_per_day: network === "mainnet" ? 5e3 : 1e7
    }
  };
  if (overrides) {
    return deepMerge(basePolicy, overrides);
  }
  return basePolicy;
}
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    const targetValue = target[key];
    if (sourceValue !== void 0 && typeof sourceValue === "object" && sourceValue !== null && !Array.isArray(sourceValue) && typeof targetValue === "object" && targetValue !== null && !Array.isArray(targetValue)) {
      result[key] = deepMerge(
        targetValue,
        sourceValue
      );
    } else if (sourceValue !== void 0) {
      result[key] = sourceValue;
    }
  }
  return result;
}

// src/keystore/secure-buffer.ts
var SecureBuffer = class _SecureBuffer {
  buffer;
  isDisposed = false;
  /**
   * Private constructor - use static factory methods.
   */
  constructor(size) {
    this.buffer = Buffer.allocUnsafe(size);
  }
  /**
   * Creates a new SecureBuffer with uninitialized content of specified size.
   *
   * @param size - Size in bytes
   * @returns New SecureBuffer instance
   */
  static alloc(size) {
    if (size <= 0) {
      throw new Error("SecureBuffer size must be positive");
    }
    const secure = new _SecureBuffer(size);
    secure.buffer.fill(0);
    return secure;
  }
  /**
   * Creates a SecureBuffer from existing data.
   *
   * IMPORTANT: The source buffer is zeroed immediately after copying
   * to prevent the original data from remaining in memory.
   *
   * @param data - Source buffer (will be zeroed)
   * @param verify - If true, verify source was zeroed (default: false for performance)
   * @returns New SecureBuffer containing the copied data
   */
  static from(data, verify2 = false) {
    if (!Buffer.isBuffer(data)) {
      throw new Error("SecureBuffer.from requires a Buffer");
    }
    if (data.length === 0) {
      throw new Error("SecureBuffer cannot be empty");
    }
    const secure = new _SecureBuffer(data.length);
    data.copy(secure.buffer);
    data.fill(0);
    if (verify2) {
      const zeroBuffer = Buffer.alloc(data.length, 0);
      if (!data.equals(zeroBuffer)) {
        throw new Error("SecureBuffer: Source buffer zeroing verification failed");
      }
    }
    return secure;
  }
  /**
   * Gets the buffer contents for use in cryptographic operations.
   *
   * @returns The internal Buffer
   * @throws Error if buffer has been disposed
   */
  getBuffer() {
    if (this.isDisposed) {
      throw new Error("SecureBuffer has been disposed");
    }
    return this.buffer;
  }
  /**
   * Disposes the buffer by securely zeroing its contents.
   *
   * This operation is irreversible. Multiple overwrite passes are used
   * to help prevent data recovery.
   */
  dispose() {
    if (!this.isDisposed) {
      this.buffer.fill(0);
      this.buffer.fill(255);
      this.buffer.fill(0);
      this.isDisposed = true;
    }
  }
  /**
   * Alias for dispose() - matches common naming conventions.
   */
  zero() {
    this.dispose();
  }
  /**
   * Returns whether the buffer has been disposed.
   */
  get disposed() {
    return this.isDisposed;
  }
  /**
   * Alias for disposed getter - matches spec naming.
   */
  get zeroed() {
    return this.isDisposed;
  }
  /**
   * Buffer length in bytes.
   */
  get length() {
    return this.buffer.length;
  }
  /**
   * Executes an operation with the buffer and ensures cleanup on completion.
   *
   * The SecureBuffer is automatically disposed after the operation,
   * regardless of success or failure.
   *
   * @param secure - SecureBuffer to use
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecure(secure, operation) {
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }
  /**
   * Creates a SecureBuffer, executes an operation, and disposes it.
   *
   * @param data - Source buffer (will be zeroed)
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecureBuffer(data, operation) {
    const secure = _SecureBuffer.from(data);
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }
  // ========================================================================
  // Serialization Prevention
  // ========================================================================
  /**
   * Prevents JSON serialization of sensitive data.
   * @throws Error always
   */
  toJSON() {
    throw new Error("SecureBuffer cannot be serialized to JSON");
  }
  /**
   * Returns a placeholder string instead of buffer contents.
   */
  toString() {
    return "[SecureBuffer]";
  }
  /**
   * Custom Node.js inspection - prevents accidental logging of contents.
   */
  [/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")]() {
    return `[SecureBuffer length=${this.length} disposed=${this.isDisposed}]`;
  }
  /**
   * Prevents spreading/iteration of buffer contents.
   */
  [Symbol.iterator]() {
    throw new Error("SecureBuffer cannot be iterated");
  }
};

// src/keystore/errors.ts
var KeystoreError = class extends Error {
  constructor(message, details) {
    super(message);
    this.details = details;
    this.name = this.constructor.name;
    this.timestamp = (/* @__PURE__ */ new Date()).toISOString();
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
  /** Timestamp when error occurred */
  timestamp;
  /** Correlation ID for tracking */
  correlationId;
  /**
   * Convert to safe JSON representation (excludes sensitive data).
   */
  toSafeJSON() {
    return {
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
      timestamp: this.timestamp,
      correlationId: this.correlationId
    };
  }
};
var KeystoreInitializationError = class extends KeystoreError {
  code = "KEYSTORE_INIT_ERROR";
  recoverable = false;
  originalCause;
  constructor(message, originalCause) {
    super(message, { cause: originalCause?.message });
    this.originalCause = originalCause;
  }
};
var WalletNotFoundError = class extends KeystoreError {
  constructor(walletId) {
    super(`Wallet not found: ${walletId}`, { walletId });
    this.walletId = walletId;
  }
  code = "WALLET_NOT_FOUND";
  recoverable = false;
};
var WalletExistsError = class extends KeystoreError {
  constructor(walletId, existingAddress) {
    super(`Wallet already exists: ${walletId}`, { walletId, existingAddress });
    this.walletId = walletId;
    this.existingAddress = existingAddress;
  }
  code = "WALLET_EXISTS";
  recoverable = false;
};
var AuthenticationError = class extends KeystoreError {
  code = "AUTHENTICATION_ERROR";
  recoverable = true;
  constructor() {
    super("Authentication failed");
  }
};
var WeakPasswordError = class extends KeystoreError {
  constructor(requirements) {
    super("Password does not meet security requirements", { requirements });
    this.requirements = requirements;
  }
  code = "WEAK_PASSWORD";
  recoverable = true;
};
var KeyDecryptionError = class extends KeystoreError {
  code = "KEY_DECRYPTION_ERROR";
  recoverable = false;
  constructor(message = "Key decryption failed") {
    super(message);
  }
};
var KeyEncryptionError = class extends KeystoreError {
  code = "KEY_ENCRYPTION_ERROR";
  recoverable = false;
  constructor(message = "Key encryption failed") {
    super(message);
  }
};
var InvalidKeyError = class extends KeystoreError {
  constructor(reason, expectedFormat) {
    super(`Invalid key format: ${reason}`, { reason, expectedFormat });
    this.reason = reason;
    this.expectedFormat = expectedFormat;
  }
  code = "INVALID_KEY_FORMAT";
  recoverable = false;
};
var KeystoreWriteError = class extends KeystoreError {
  constructor(message, operation) {
    super(message, { operation });
    this.operation = operation;
  }
  code = "KEYSTORE_WRITE_ERROR";
  recoverable = true;
};
var KeystoreReadError = class extends KeystoreError {
  code = "KEYSTORE_READ_ERROR";
  recoverable = true;
  constructor(message) {
    super(message);
  }
};
var KeystoreCapacityError = class extends KeystoreError {
  constructor(network, currentCount, maxCount) {
    super(`Keystore capacity exceeded for ${network}`, {
      network,
      currentCount,
      maxCount
    });
    this.network = network;
    this.currentCount = currentCount;
    this.maxCount = maxCount;
  }
  code = "KEYSTORE_CAPACITY_ERROR";
  recoverable = false;
};
var BackupFormatError = class extends KeystoreError {
  constructor(reason, expectedVersion) {
    super(`Invalid backup format: ${reason}`, { reason, expectedVersion });
    this.reason = reason;
    this.expectedVersion = expectedVersion;
  }
  code = "BACKUP_FORMAT_ERROR";
  recoverable = false;
};
var NetworkMismatchError = class extends KeystoreError {
  constructor(walletNetwork, requestedNetwork) {
    super(`Network mismatch: wallet is ${walletNetwork}, requested ${requestedNetwork}`, {
      walletNetwork,
      requestedNetwork
    });
    this.walletNetwork = walletNetwork;
    this.requestedNetwork = requestedNetwork;
  }
  code = "NETWORK_MISMATCH";
  recoverable = false;
};
var ProviderUnavailableError = class extends KeystoreError {
  constructor(providerType, reason) {
    super(`Provider unavailable: ${reason}`, { providerType, reason });
    this.providerType = providerType;
    this.reason = reason;
  }
  code = "PROVIDER_UNAVAILABLE";
  recoverable = true;
};
function isKeystoreError(error) {
  return error instanceof KeystoreError;
}
function isKeystoreErrorCode(error, code) {
  return isKeystoreError(error) && error.code === code;
}
var ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  // 64 MB
  timeCost: 3,
  // 3 iterations
  parallelism: 4,
  // 4 threads
  hashLength: 32,
  // 256-bit output
  saltLength: 32
  // 256-bit salt
};
var AES_CONFIG = {
  algorithm: "aes-256-gcm",
  keyLength: 32,
  // 256 bits
  ivLength: 12,
  // 96 bits (NIST recommended for GCM)
  authTagLength: 16
  // 128 bits
};
var PERMISSIONS = {
  FILE: 384,
  // Owner read/write only (rw-------)
  DIRECTORY: 448
  // Owner read/write/execute only (rwx------)
};
var DEFAULT_PASSWORD_POLICY = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128
};
var RATE_LIMIT_CONFIG = {
  maxAttempts: 5,
  // Max failed attempts
  windowSeconds: 900,
  // 15 minute window
  lockoutSeconds: 1800,
  // 30 minute initial lockout
  lockoutMultiplier: 2
  // Doubles each time
};
function validatePassword(password, policy) {
  const errors = [];
  if (password.length < policy.minLength) {
    errors.push(`Minimum ${policy.minLength} characters required`);
  }
  if (password.length > policy.maxLength) {
    errors.push(`Maximum ${policy.maxLength} characters allowed`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Must contain uppercase letter");
  }
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push("Must contain lowercase letter");
  }
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push("Must contain number");
  }
  if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push("Must contain special character");
  }
  return errors;
}
var FileLock = class _FileLock {
  inProcessLocks = /* @__PURE__ */ new Map();
  static LOCK_TIMEOUT_MS = 3e4;
  // 30 seconds
  static STALE_LOCK_THRESHOLD_MS = 6e4;
  // 1 minute
  /**
   * Executes operation with exclusive access to the file.
   * Uses both in-process and file-system level locks for cross-process safety.
   */
  async withLock(key, operation) {
    while (this.inProcessLocks.has(key)) {
      await this.inProcessLocks.get(key);
    }
    let releaseLock;
    const lockPromise = new Promise((resolve2) => {
      releaseLock = resolve2;
    });
    this.inProcessLocks.set(key, lockPromise);
    const lockPath = `${key}.lock`;
    try {
      await this.acquireFileLock(lockPath);
      try {
        return await operation();
      } finally {
        await this.releaseFileLock(lockPath);
      }
    } finally {
      this.inProcessLocks.delete(key);
      releaseLock();
    }
  }
  /**
   * Acquire a file-based lock.
   * Creates a lock file with PID and timestamp for stale detection.
   */
  async acquireFileLock(lockPath) {
    const startTime = Date.now();
    while (Date.now() - startTime < _FileLock.LOCK_TIMEOUT_MS) {
      try {
        const lockContent = await promises.readFile(lockPath, "utf-8").catch(() => null);
        if (lockContent) {
          const lockData2 = JSON.parse(lockContent);
          const lockAge = Date.now() - new Date(lockData2.timestamp).getTime();
          if (lockAge > _FileLock.STALE_LOCK_THRESHOLD_MS) {
            await promises.unlink(lockPath).catch(() => {
            });
          } else {
            await new Promise((resolve2) => setTimeout(resolve2, 50));
            continue;
          }
        }
        const lockData = {
          pid: process.pid,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        await promises.writeFile(lockPath, JSON.stringify(lockData), {
          flag: "wx",
          // Exclusive create - fails if file exists
          mode: 384
        });
        return;
      } catch (error) {
        if (error?.code === "EEXIST") {
          await new Promise((resolve2) => setTimeout(resolve2, 50));
          continue;
        }
        return;
      }
    }
    console.warn(`[FileLock] Timeout acquiring lock for ${lockPath}, proceeding with in-process lock only`);
  }
  /**
   * Release a file-based lock.
   */
  async releaseFileLock(lockPath) {
    try {
      await promises.unlink(lockPath);
    } catch {
    }
  }
};
var LocalKeystore = class {
  providerType = "local-file";
  providerVersion = "1.0.0";
  baseDir = "";
  passwordPolicy = DEFAULT_PASSWORD_POLICY;
  maxWalletsPerNetwork = 100;
  initialized = false;
  fileLock = new FileLock();
  // Rate limiting state
  authAttempts = /* @__PURE__ */ new Map();
  lockouts = /* @__PURE__ */ new Map();
  rateLimitStatePath = "";
  // ========================================================================
  // Lifecycle Methods
  // ========================================================================
  async initialize(config) {
    if (this.initialized) {
      throw new KeystoreInitializationError("Provider already initialized");
    }
    const homeDir = process.env["HOME"] || "";
    this.baseDir = config.baseDir ? path2.resolve(config.baseDir.replace(/^~/, homeDir)) : path2.join(homeDir, ".xrpl-wallet-mcp");
    this.rateLimitStatePath = path2.join(this.baseDir, ".rate-limit-state.json");
    if (config.passwordPolicy) {
      this.passwordPolicy = { ...DEFAULT_PASSWORD_POLICY, ...config.passwordPolicy };
    }
    if (config.maxWalletsPerNetwork !== void 0) {
      this.maxWalletsPerNetwork = config.maxWalletsPerNetwork;
    }
    await this.ensureDirectoryStructure();
    await this.verifyPermissions();
    await this.restoreRateLimitState();
    this.initialized = true;
  }
  /**
   * Persist rate limiting state to disk.
   * Called after auth attempts and lockouts change.
   */
  async persistRateLimitState() {
    if (!this.baseDir) return;
    const state = {
      version: 1,
      updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      lockouts: Array.from(this.lockouts.entries()).map(([walletId, date]) => ({
        walletId,
        lockedUntil: date.toISOString()
      })),
      authAttempts: Array.from(this.authAttempts.entries()).map(([walletId, attempts]) => ({
        walletId,
        attempts: attempts.map((a) => ({
          timestamp: a.timestamp.toISOString(),
          success: a.success,
          reason: a.reason
        }))
      }))
    };
    try {
      await this.atomicWrite(this.rateLimitStatePath, JSON.stringify(state, null, 2));
    } catch (error) {
      console.warn("Failed to persist rate limit state:", error);
    }
  }
  /**
   * Restore rate limiting state from disk.
   * Called during initialization.
   */
  async restoreRateLimitState() {
    try {
      const content = await promises.readFile(this.rateLimitStatePath, "utf-8");
      const state = JSON.parse(content);
      this.lockouts.clear();
      this.authAttempts.clear();
      const now = /* @__PURE__ */ new Date();
      for (const entry of state.lockouts || []) {
        const lockedUntil = new Date(entry.lockedUntil);
        if (lockedUntil > now) {
          this.lockouts.set(entry.walletId, lockedUntil);
        }
      }
      const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1e3);
      for (const entry of state.authAttempts || []) {
        const recentAttempts = (entry.attempts || []).map((a) => ({
          timestamp: new Date(a.timestamp),
          success: a.success,
          reason: a.reason
        })).filter((a) => a.timestamp > twentyFourHoursAgo);
        if (recentAttempts.length > 0) {
          this.authAttempts.set(entry.walletId, recentAttempts);
        }
      }
      console.log(
        `[LocalKeystore] Restored rate limit state: ${this.lockouts.size} lockouts, ${this.authAttempts.size} wallets with auth history`
      );
    } catch (error) {
      this.lockouts.clear();
      this.authAttempts.clear();
    }
  }
  async healthCheck() {
    this.assertInitialized();
    const errors = [];
    let storageAccessible = true;
    let encryptionAvailable = true;
    let networkCount = 0;
    let walletCount = 0;
    try {
      await promises.access(this.baseDir, promises.constants.R_OK | promises.constants.W_OK);
    } catch {
      storageAccessible = false;
      errors.push("Base directory not accessible");
    }
    try {
      const testKey = crypto.randomBytes(32);
      const testIv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", testKey, testIv);
      cipher.update("test");
      cipher.final();
    } catch {
      encryptionAvailable = false;
      errors.push("AES-256-GCM encryption not available");
    }
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const networkDir = path2.join(this.baseDir, network, "wallets");
      try {
        await promises.access(networkDir);
        networkCount++;
        const files = await promises.readdir(networkDir);
        walletCount += files.filter((f) => f.endsWith(".wallet.json")).length;
      } catch {
      }
    }
    const result = {
      healthy: storageAccessible && encryptionAvailable && errors.length === 0,
      providerType: this.providerType,
      providerVersion: this.providerVersion,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      details: {
        storageAccessible,
        encryptionAvailable,
        networkCount,
        walletCount
      }
    };
    if (errors.length > 0) {
      result.errors = errors;
    }
    return result;
  }
  async close() {
    this.authAttempts.clear();
    this.lockouts.clear();
    this.initialized = false;
  }
  // ========================================================================
  // Wallet CRUD Operations
  // ========================================================================
  async createWallet(network, policy, options) {
    this.assertInitialized();
    if (!options?.password) {
      throw new WeakPasswordError(["Password is required"]);
    }
    const passwordErrors = validatePassword(options.password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    const currentCount = (await this.listWallets(network)).length;
    if (currentCount >= this.maxWalletsPerNetwork) {
      throw new KeystoreCapacityError(network, currentCount, this.maxWalletsPerNetwork);
    }
    const walletId = this.generateWalletId();
    const algorithm = options?.algorithm || "ed25519";
    const xrplAlgorithm = algorithm === "secp256k1" ? ECDSA.secp256k1 : ECDSA.ed25519;
    const xrplWallet = Wallet.generate(xrplAlgorithm);
    const seedString = xrplWallet.seed;
    if (!seedString) {
      throw new KeystoreWriteError("Failed to generate wallet seed", "create");
    }
    const seedBuffer = Buffer.from(seedString, "utf-8");
    const seed = SecureBuffer.from(seedBuffer);
    try {
      const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const kek = await this.deriveKey(options.password, salt);
      const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), kek);
      kek.dispose();
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const entry = {
        walletId,
        name: options?.name || `Wallet ${walletId.slice(0, 8)}`,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm,
        network,
        policyId: policy.policyId,
        encryption: {
          algorithm: "aes-256-gcm",
          kdf: "argon2id",
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism
          },
          salt: salt.toString("base64")
        },
        metadata: {
          ...options?.description && { description: options.description },
          ...options?.tags && { tags: options.tags }
        },
        createdAt: now,
        modifiedAt: now,
        status: "active"
      };
      const walletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        }
      };
      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
      await this.updateIndex(network, entry, "add");
      return entry;
    } finally {
      seed.dispose();
    }
  }
  async loadKey(walletId, password) {
    this.assertInitialized();
    this.checkRateLimit(walletId);
    try {
      const { walletFile } = await this.findWallet(walletId);
      const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
      const kek = await this.deriveKey(password, salt);
      try {
        const encryptedData = Buffer.from(walletFile.encryptedKey.data, "base64");
        const iv = Buffer.from(walletFile.encryptedKey.iv, "base64");
        const authTag = Buffer.from(walletFile.encryptedKey.authTag, "base64");
        const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
        await this.recordAuthSuccess(walletId);
        return decrypted;
      } finally {
        kek.dispose();
      }
    } catch (error) {
      if (error instanceof AuthenticationError || error instanceof KeyDecryptionError) {
        await this.recordAuthFailure(walletId);
      }
      throw error;
    }
  }
  async storeKey(walletId, key, password, metadata) {
    this.assertInitialized();
    const passwordErrors = validatePassword(password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    try {
      await this.findWallet(walletId);
      throw new WalletExistsError(walletId);
    } catch (error) {
      if (!(error instanceof WalletNotFoundError)) {
        throw error;
      }
    }
    const keyBuffer = key.getBuffer();
    const validLengths = [16, 29, 30, 31, 32, 33, 34, 35];
    if (!validLengths.some((len) => Math.abs(keyBuffer.length - len) <= 2)) {
      throw new InvalidKeyError(
        "Invalid key length",
        `Expected 16 bytes (entropy), 29-35 bytes (seed string), or 32-33 bytes (private key), got ${keyBuffer.length}`
      );
    }
    let xrplWallet;
    try {
      if (keyBuffer.length === 16) {
        xrplWallet = Wallet.fromEntropy(keyBuffer);
      } else if (keyBuffer.length >= 29 && keyBuffer.length <= 35) {
        const seedString = keyBuffer.toString("utf-8");
        xrplWallet = Wallet.fromSeed(seedString);
      } else {
        try {
          xrplWallet = Wallet.fromEntropy(keyBuffer.slice(0, 16));
        } catch {
          throw new InvalidKeyError("Could not derive wallet from key");
        }
      }
    } catch (error) {
      if (error instanceof InvalidKeyError) throw error;
      throw new InvalidKeyError("Could not derive wallet from key");
    }
    const network = "testnet";
    const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
    const kek = await this.deriveKey(password, salt);
    try {
      const { encryptedData, iv, authTag } = await this.encrypt(keyBuffer, kek);
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const entry = {
        walletId,
        name: walletId,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm: "ed25519",
        network,
        policyId: "imported",
        encryption: {
          algorithm: "aes-256-gcm",
          kdf: "argon2id",
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism
          },
          salt: salt.toString("base64")
        },
        metadata,
        createdAt: now,
        modifiedAt: now,
        status: "active"
      };
      const walletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        }
      };
      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
      await this.updateIndex(network, entry, "add");
    } finally {
      kek.dispose();
    }
  }
  async listWallets(network) {
    this.assertInitialized();
    const networks = network ? [network] : ["mainnet", "testnet", "devnet"];
    const summaries = [];
    for (const net of networks) {
      const indexPath = path2.join(this.baseDir, net, "index.json");
      try {
        const content = await promises.readFile(indexPath, "utf-8");
        const index = JSON.parse(content);
        for (const entry of index.wallets) {
          const summary = {
            walletId: entry.walletId,
            name: entry.name,
            address: entry.address,
            network: entry.network,
            status: entry.status,
            createdAt: entry.createdAt,
            policyId: entry.policyId
          };
          if (entry.metadata?.lastUsedAt) {
            summary.lastUsedAt = entry.metadata.lastUsedAt;
          }
          if (entry.metadata?.tags) {
            summary.tags = entry.metadata.tags;
          }
          summaries.push(summary);
        }
      } catch {
      }
    }
    return summaries;
  }
  async getWallet(walletId) {
    this.assertInitialized();
    const { walletFile } = await this.findWallet(walletId);
    return walletFile.entry;
  }
  async deleteWallet(walletId, password) {
    this.assertInitialized();
    this.checkRateLimit(walletId);
    const { network, walletFile, filePath } = await this.findWallet(walletId);
    const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
    const kek = await this.deriveKey(password, salt);
    try {
      const encryptedData = Buffer.from(walletFile.encryptedKey.data, "base64");
      const iv = Buffer.from(walletFile.encryptedKey.iv, "base64");
      const authTag = Buffer.from(walletFile.encryptedKey.authTag, "base64");
      const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
      decrypted.dispose();
      await this.recordAuthSuccess(walletId);
    } catch (error) {
      await this.recordAuthFailure(walletId);
      throw error;
    } finally {
      kek.dispose();
    }
    await this.fileLock.withLock(filePath, async () => {
      const fileSize = (await promises.stat(filePath)).size;
      const randomData = crypto.randomBytes(fileSize);
      await promises.writeFile(filePath, randomData);
      await promises.unlink(filePath);
    });
    await this.updateIndex(network, walletFile.entry, "remove");
  }
  async rotateKey(walletId, currentPassword, newPassword) {
    this.assertInitialized();
    const passwordErrors = validatePassword(newPassword, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    const key = await this.loadKey(walletId, currentPassword);
    try {
      const { network, walletFile, filePath } = await this.findWallet(walletId);
      const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const newKek = await this.deriveKey(newPassword, newSalt);
      try {
        const { encryptedData, iv, authTag } = await this.encrypt(key.getBuffer(), newKek);
        walletFile.entry.encryption.salt = newSalt.toString("base64");
        walletFile.entry.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
        walletFile.encryptedKey = {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        };
        await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));
        await this.updateIndex(network, walletFile.entry, "update");
      } finally {
        newKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }
  async updateMetadata(walletId, updates) {
    this.assertInitialized();
    const { network, walletFile, filePath } = await this.findWallet(walletId);
    walletFile.entry.metadata = {
      ...walletFile.entry.metadata,
      ...updates
    };
    walletFile.entry.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
    await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));
    await this.updateIndex(network, walletFile.entry, "update");
  }
  /**
   * Store a regular key for a wallet.
   *
   * This allows the wallet to sign transactions with the regular key
   * instead of the master key, providing better security through key rotation.
   *
   * @param walletId - Unique wallet identifier
   * @param regularKeySeed - Regular key seed (base58 encoded)
   * @param regularKeyAddress - Regular key's XRPL address
   * @param password - User password for encryption
   */
  async storeRegularKey(walletId, regularKeySeed, regularKeyAddress, password) {
    this.assertInitialized();
    const masterKey = await this.loadKey(walletId, password);
    masterKey.dispose();
    const { network, walletFile, filePath } = await this.findWallet(walletId);
    const regularKeySeedBuffer = Buffer.from(regularKeySeed, "utf-8");
    const regularKeySecure = SecureBuffer.from(regularKeySeedBuffer);
    try {
      const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
      const kek = await this.deriveKey(password, salt);
      try {
        const { encryptedData, iv, authTag } = await this.encrypt(
          regularKeySecure.getBuffer(),
          kek
        );
        const regularKeyFile = {
          version: 1,
          walletId,
          regularKeyAddress,
          encryptedKey: {
            data: encryptedData.toString("base64"),
            iv: iv.toString("base64"),
            authTag: authTag.toString("base64")
          },
          createdAt: (/* @__PURE__ */ new Date()).toISOString()
        };
        const regularKeyPath = path2.join(
          this.baseDir,
          network,
          "wallets",
          `${walletId}.regular-key.json`
        );
        await this.atomicWrite(regularKeyPath, JSON.stringify(regularKeyFile, null, 2));
        walletFile.entry.metadata = {
          ...walletFile.entry.metadata,
          hasRegularKey: true,
          customData: {
            ...walletFile.entry.metadata?.customData,
            regularKeyAddress,
            regularKeyStoredAt: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
        walletFile.entry.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
        await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));
        await this.updateIndex(network, walletFile.entry, "update");
      } finally {
        kek.dispose();
      }
    } finally {
      regularKeySecure.dispose();
    }
  }
  /**
   * Load the regular key for a wallet.
   *
   * @param walletId - Unique wallet identifier
   * @param password - User password for decryption
   * @returns SecureBuffer containing the regular key seed, or null if no regular key
   */
  async loadRegularKey(walletId, password) {
    this.assertInitialized();
    const { network, walletFile } = await this.findWallet(walletId);
    const regularKeyPath = path2.join(
      this.baseDir,
      network,
      "wallets",
      `${walletId}.regular-key.json`
    );
    let regularKeyFile;
    try {
      const content = await promises.readFile(regularKeyPath, "utf-8");
      regularKeyFile = JSON.parse(content);
    } catch {
      return null;
    }
    const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
    const kek = await this.deriveKey(password, salt);
    try {
      const encryptedData = Buffer.from(regularKeyFile.encryptedKey.data, "base64");
      const iv = Buffer.from(regularKeyFile.encryptedKey.iv, "base64");
      const authTag = Buffer.from(regularKeyFile.encryptedKey.authTag, "base64");
      return await this.decrypt(encryptedData, kek, iv, authTag);
    } finally {
      kek.dispose();
    }
  }
  async exportBackup(walletId, password, format) {
    this.assertInitialized();
    const key = await this.loadKey(walletId, password);
    try {
      const { walletFile } = await this.findWallet(walletId);
      const seedHex = key.getBuffer().toString("hex");
      const payloadStr = JSON.stringify({
        version: 1,
        exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
        wallet: {
          entry: walletFile.entry,
          seed: seedHex
        }
      });
      const payloadBuffer = Buffer.from(payloadStr);
      const backupSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const backupKek = await this.deriveKey(password, backupSalt);
      try {
        const { encryptedData, iv, authTag } = await this.encrypt(payloadBuffer, backupKek);
        payloadBuffer.fill(0);
        const checksum = crypto.createHash("sha256").update(encryptedData).digest("hex");
        const backup = {
          version: 1,
          format,
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          sourceProvider: this.providerType,
          encryption: {
            algorithm: "aes-256-gcm",
            kdf: "argon2id",
            kdfParams: {
              memoryCost: ARGON2_CONFIG.memoryCost,
              timeCost: ARGON2_CONFIG.timeCost,
              parallelism: ARGON2_CONFIG.parallelism
            },
            salt: backupSalt.toString("base64"),
            iv: iv.toString("base64"),
            authTag: authTag.toString("base64")
          },
          payload: encryptedData.toString("base64"),
          checksum
        };
        return backup;
      } finally {
        backupKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }
  async importBackup(backup, password, options) {
    this.assertInitialized();
    if (backup.version !== 1) {
      throw new BackupFormatError("Unsupported backup version", 1);
    }
    const payloadData = Buffer.from(backup.payload, "base64");
    const computedChecksum = crypto.createHash("sha256").update(payloadData).digest("hex");
    if (computedChecksum !== backup.checksum) {
      throw new BackupFormatError("Checksum verification failed");
    }
    const salt = Buffer.from(backup.encryption.salt, "base64");
    const kek = await this.deriveKey(password, salt);
    let decryptedPayload;
    try {
      const iv = Buffer.from(backup.encryption.iv, "base64");
      const authTag = Buffer.from(backup.encryption.authTag, "base64");
      decryptedPayload = await this.decrypt(payloadData, kek, iv, authTag);
    } finally {
      kek.dispose();
    }
    try {
      const payload = JSON.parse(decryptedPayload.getBuffer().toString());
      const walletId = options?.newName || payload.wallet.entry.walletId;
      const targetNetwork = options?.targetNetwork || payload.wallet.entry.network;
      try {
        await this.findWallet(walletId);
        if (!options?.force) {
          throw new WalletExistsError(walletId);
        }
      } catch (error) {
        if (!(error instanceof WalletNotFoundError)) {
          throw error;
        }
      }
      const seedBuffer = Buffer.from(payload.wallet.seed, "hex");
      const seed = SecureBuffer.from(seedBuffer);
      try {
        const storePassword = options?.newPassword || password;
        const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
        const newKek = await this.deriveKey(storePassword, newSalt);
        try {
          const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), newKek);
          const now = (/* @__PURE__ */ new Date()).toISOString();
          const entry = {
            ...payload.wallet.entry,
            walletId,
            network: targetNetwork,
            encryption: {
              algorithm: "aes-256-gcm",
              kdf: "argon2id",
              kdfParams: {
                memoryCost: ARGON2_CONFIG.memoryCost,
                timeCost: ARGON2_CONFIG.timeCost,
                parallelism: ARGON2_CONFIG.parallelism
              },
              salt: newSalt.toString("base64")
            },
            modifiedAt: now,
            metadata: {
              ...payload.wallet.entry.metadata || {},
              customData: {
                ...payload.wallet.entry.metadata?.customData || {},
                importedAt: now,
                importedFrom: backup.sourceProvider
              }
            }
          };
          const walletFile = {
            version: 1,
            walletId,
            entry,
            encryptedKey: {
              data: encryptedData.toString("base64"),
              iv: iv.toString("base64"),
              authTag: authTag.toString("base64")
            }
          };
          const walletPath = this.getWalletPath(targetNetwork, walletId);
          await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
          await this.updateIndex(targetNetwork, entry, "add");
          return entry;
        } finally {
          newKek.dispose();
        }
      } finally {
        seed.dispose();
      }
    } finally {
      decryptedPayload.dispose();
    }
  }
  // ========================================================================
  // Private Helper Methods
  // ========================================================================
  assertInitialized() {
    if (!this.initialized) {
      throw new KeystoreInitializationError("Provider not initialized");
    }
  }
  async ensureDirectoryStructure() {
    await promises.mkdir(this.baseDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const walletsDir = path2.join(this.baseDir, network, "wallets");
      await promises.mkdir(walletsDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
    }
    const backupDir = path2.join(this.baseDir, "backups");
    await promises.mkdir(backupDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
  }
  async verifyPermissions() {
    const stats = await promises.stat(this.baseDir);
    const mode = stats.mode & 511;
    if (mode !== PERMISSIONS.DIRECTORY) {
      await promises.chmod(this.baseDir, PERMISSIONS.DIRECTORY);
    }
  }
  generateWalletId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString("hex");
    return `wallet_${timestamp}_${random}`;
  }
  getWalletPath(network, walletId) {
    return path2.join(this.baseDir, network, "wallets", `${walletId}.wallet.json`);
  }
  async findWallet(walletId) {
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const filePath = this.getWalletPath(network, walletId);
      try {
        const content = await promises.readFile(filePath, "utf-8");
        const walletFile = JSON.parse(content);
        return { network, walletFile, filePath };
      } catch {
      }
    }
    throw new WalletNotFoundError(walletId);
  }
  async updateIndex(network, entry, operation) {
    const indexPath = path2.join(this.baseDir, network, "index.json");
    await this.fileLock.withLock(indexPath, async () => {
      let index;
      try {
        const content = await promises.readFile(indexPath, "utf-8");
        index = JSON.parse(content);
      } catch {
        index = { version: 1, wallets: [], modifiedAt: "" };
      }
      switch (operation) {
        case "add":
          index.wallets.push(entry);
          break;
        case "remove":
          index.wallets = index.wallets.filter((w) => w.walletId !== entry.walletId);
          break;
        case "update":
          index.wallets = index.wallets.map((w) => w.walletId === entry.walletId ? entry : w);
          break;
      }
      index.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
      await this.atomicWrite(indexPath, JSON.stringify(index, null, 2));
    });
  }
  // ========================================================================
  // Cryptographic Operations
  // ========================================================================
  /**
   * Derives a 256-bit key from password using Argon2id.
   */
  async deriveKey(password, salt) {
    const derivedKey = await argon2.hash(password, {
      type: ARGON2_CONFIG.type,
      memoryCost: ARGON2_CONFIG.memoryCost,
      timeCost: ARGON2_CONFIG.timeCost,
      parallelism: ARGON2_CONFIG.parallelism,
      hashLength: ARGON2_CONFIG.hashLength,
      salt,
      raw: true
      // Return raw bytes, not encoded string
    });
    return SecureBuffer.from(derivedKey);
  }
  /**
   * Encrypts data using AES-256-GCM.
   */
  async encrypt(plaintext, key) {
    const iv = crypto.randomBytes(AES_CONFIG.ivLength);
    const cipher = crypto.createCipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
      authTagLength: AES_CONFIG.authTagLength
    });
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      encryptedData: encrypted,
      iv,
      authTag
    };
  }
  /**
   * Decrypts data using AES-256-GCM.
   */
  async decrypt(ciphertext, key, iv, authTag) {
    try {
      const decipher = crypto.createDecipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
        authTagLength: AES_CONFIG.authTagLength
      });
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return SecureBuffer.from(decrypted);
    } catch (error) {
      if (error instanceof Error && error.message.includes("auth")) {
        throw new AuthenticationError();
      }
      throw new KeyDecryptionError("Decryption failed");
    }
  }
  // ========================================================================
  // File System Operations
  // ========================================================================
  /**
   * Atomically writes content to a file using temp file + rename pattern.
   */
  async atomicWrite(filePath, content) {
    const dir = path2.dirname(filePath);
    const tempPath = path2.join(dir, `.${path2.basename(filePath)}.tmp.${process.pid}`);
    try {
      await promises.writeFile(tempPath, content, {
        encoding: "utf-8",
        mode: PERMISSIONS.FILE
      });
      await promises.rename(tempPath, filePath);
    } catch (error) {
      try {
        await promises.unlink(tempPath);
      } catch {
      }
      throw new KeystoreWriteError(`Failed to write ${filePath}: ${error}`, "create");
    }
  }
  // ========================================================================
  // Rate Limiting
  // ========================================================================
  /**
   * Checks if wallet is currently locked out.
   */
  checkRateLimit(walletId) {
    const lockout = this.lockouts.get(walletId);
    if (lockout && lockout > /* @__PURE__ */ new Date()) {
      throw new AuthenticationError();
    }
    if (lockout) {
      this.lockouts.delete(walletId);
    }
  }
  /**
   * Records successful authentication.
   */
  async recordAuthSuccess(walletId) {
    this.authAttempts.delete(walletId);
    this.lockouts.delete(walletId);
    await this.persistRateLimitState();
  }
  /**
   * Records failed authentication attempt.
   */
  async recordAuthFailure(walletId) {
    const now = /* @__PURE__ */ new Date();
    const windowStart = new Date(now.getTime() - RATE_LIMIT_CONFIG.windowSeconds * 1e3);
    let attempts = this.authAttempts.get(walletId) || [];
    attempts = attempts.filter((a) => a.timestamp > windowStart);
    attempts.push({ timestamp: now, success: false });
    this.authAttempts.set(walletId, attempts);
    const failures = attempts.filter((a) => !a.success).length;
    if (failures >= RATE_LIMIT_CONFIG.maxAttempts) {
      const lockoutCount = Math.floor(failures / RATE_LIMIT_CONFIG.maxAttempts);
      const duration = RATE_LIMIT_CONFIG.lockoutSeconds * Math.pow(RATE_LIMIT_CONFIG.lockoutMultiplier, lockoutCount - 1);
      const lockoutUntil = new Date(now.getTime() + duration * 1e3);
      this.lockouts.set(walletId, lockoutUntil);
    }
    await this.persistRateLimitState();
  }
};

// src/keystore/index.ts
var DEFAULT_PASSWORD_POLICY2 = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128
};
var ARGON2_CONFIG2 = {
  memoryCost: 65536,
  // 64 MB
  timeCost: 3,
  // 3 iterations
  parallelism: 4,
  // 4 threads
  hashLength: 32,
  // 256-bit output
  saltLength: 32
  // 256-bit salt
};
var AES_CONFIG2 = {
  algorithm: "aes-256-gcm",
  keyLength: 32,
  // 256 bits
  ivLength: 12,
  // 96 bits
  authTagLength: 16
  // 128 bits
};

// src/xrpl/config.ts
var NETWORK_ENDPOINTS = {
  mainnet: {
    websocket: {
      primary: "wss://xrplcluster.com",
      backup: ["wss://s1.ripple.com", "wss://s2.ripple.com"]
    },
    jsonRpc: {
      primary: "https://xrplcluster.com",
      backup: ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"]
    }
  },
  testnet: {
    websocket: {
      primary: "wss://s.altnet.rippletest.net:51233",
      backup: ["wss://testnet.xrpl-labs.com"]
    },
    jsonRpc: {
      primary: "https://s.altnet.rippletest.net:51234",
      backup: []
    }
  },
  devnet: {
    websocket: {
      primary: "wss://s.devnet.rippletest.net:51233",
      backup: []
    },
    jsonRpc: {
      primary: "https://s.devnet.rippletest.net:51234",
      backup: []
    }
  }
};
var EXPLORER_URLS = {
  mainnet: {
    home: "https://xrpscan.com",
    account: (address) => `https://xrpscan.com/account/${address}`,
    transaction: (hash2) => `https://xrpscan.com/tx/${hash2}`,
    ledger: (index) => `https://xrpscan.com/ledger/${index}`
  },
  testnet: {
    home: "https://testnet.xrpl.org",
    account: (address) => `https://testnet.xrpl.org/accounts/${address}`,
    transaction: (hash2) => `https://testnet.xrpl.org/transactions/${hash2}`,
    ledger: (index) => `https://testnet.xrpl.org/ledgers/${index}`
  },
  devnet: {
    home: "https://devnet.xrpl.org",
    account: (address) => `https://devnet.xrpl.org/accounts/${address}`,
    transaction: (hash2) => `https://devnet.xrpl.org/transactions/${hash2}`,
    ledger: (index) => `https://devnet.xrpl.org/ledgers/${index}`
  }
};
var FAUCET_CONFIG = {
  mainnet: {
    available: false
    // No faucet for mainnet - real XRP must be acquired through exchanges
  },
  testnet: {
    available: true,
    url: "https://faucet.altnet.rippletest.net/accounts",
    amountXrp: 100,
    // Updated: was 1000, now ~100 XRP
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  },
  devnet: {
    available: true,
    url: "https://faucet.devnet.rippletest.net/accounts",
    amountXrp: 100,
    // Updated: was 1000, now ~100 XRP
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  }
};
var DEFAULT_CONNECTION_CONFIG = {
  connectionTimeout: 1e4,
  // 10 seconds
  requestTimeout: 3e4,
  // 30 seconds
  maxReconnectAttempts: 3,
  reconnectDelay: 1e3,
  // 1 second
  reconnectBackoff: 2
  // Exponential backoff multiplier
};
function getWebSocketUrl(network) {
  const envKey = `XRPL_${network.toUpperCase()}_WEBSOCKET_URL`;
  const customUrl = process.env[envKey];
  if (customUrl) {
    if (!customUrl.startsWith("wss://") && !customUrl.startsWith("ws://localhost")) {
      throw new Error(
        `Custom endpoint must use WSS or ws://localhost: ${envKey}=${customUrl}`
      );
    }
    return customUrl;
  }
  return NETWORK_ENDPOINTS[network].websocket.primary;
}
function getBackupWebSocketUrls(network) {
  return NETWORK_ENDPOINTS[network].websocket.backup;
}
function getTransactionExplorerUrl(hash2, network) {
  return EXPLORER_URLS[network].transaction(hash2);
}
function getAccountExplorerUrl(address, network) {
  return EXPLORER_URLS[network].account(address);
}
function getLedgerExplorerUrl(index, network) {
  return EXPLORER_URLS[network].ledger(index);
}
function isFaucetAvailable(network) {
  return FAUCET_CONFIG[network].available;
}
function getFaucetUrl(network) {
  const config = FAUCET_CONFIG[network];
  return config.available ? config.url : null;
}
function getConnectionConfig() {
  const env = process.env;
  return {
    connectionTimeout: parseInt(
      env["XRPL_CONNECTION_TIMEOUT"] ?? String(DEFAULT_CONNECTION_CONFIG.connectionTimeout)
    ),
    requestTimeout: parseInt(
      env["XRPL_REQUEST_TIMEOUT"] ?? String(DEFAULT_CONNECTION_CONFIG.requestTimeout)
    ),
    maxReconnectAttempts: parseInt(
      env["XRPL_MAX_RECONNECT_ATTEMPTS"] ?? String(DEFAULT_CONNECTION_CONFIG.maxReconnectAttempts)
    ),
    reconnectDelay: DEFAULT_CONNECTION_CONFIG.reconnectDelay,
    reconnectBackoff: DEFAULT_CONNECTION_CONFIG.reconnectBackoff
  };
}

// src/xrpl/client.ts
var XRPLClientError = class extends Error {
  constructor(message, code, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "XRPLClientError";
  }
};
var ConnectionError = class extends XRPLClientError {
  constructor(message, details) {
    super(message, "CONNECTION_ERROR", details);
    this.name = "ConnectionError";
  }
};
var AccountNotFoundError = class extends XRPLClientError {
  constructor(address) {
    super(`Account not found: ${address}`, "ACCOUNT_NOT_FOUND", { address });
    this.name = "AccountNotFoundError";
  }
};
var TransactionTimeoutError = class extends XRPLClientError {
  constructor(hash2) {
    super(`Transaction not validated: ${hash2}`, "TX_TIMEOUT", { hash: hash2 });
    this.name = "TransactionTimeoutError";
  }
};
var MaxReconnectAttemptsError = class extends XRPLClientError {
  constructor(attempts) {
    super(`Maximum reconnection attempts reached: ${attempts}`, "MAX_RECONNECT", { attempts });
    this.name = "MaxReconnectAttemptsError";
  }
};
function sleep(ms) {
  return new Promise((resolve2) => setTimeout(resolve2, ms));
}
function withTimeout(promise, ms, operation) {
  return new Promise((resolve2, reject) => {
    const timer = setTimeout(() => {
      reject(new XRPLClientError(`Operation timed out: ${operation}`, "TIMEOUT", { operation, timeoutMs: ms }));
    }, ms);
    promise.then((result) => {
      clearTimeout(timer);
      resolve2(result);
    }).catch((error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}
var XRPLClientWrapper = class {
  client;
  network;
  nodeUrl;
  backupUrls;
  connectionConfig;
  currentUrlIndex = 0;
  reconnectAttempts = 0;
  isConnected = false;
  /**
   * Create a new XRPL client wrapper
   *
   * @param config - Client configuration
   */
  constructor(config) {
    this.network = config.network;
    this.nodeUrl = config.nodeUrl ?? getWebSocketUrl(config.network);
    this.backupUrls = getBackupWebSocketUrls(config.network);
    this.connectionConfig = {
      ...getConnectionConfig(),
      ...config.connectionConfig
    };
    this.client = new Client(this.nodeUrl);
  }
  /**
   * Get the current network
   */
  getNetwork() {
    return this.network;
  }
  /**
   * Check if client is connected
   */
  isClientConnected() {
    return this.isConnected && this.client.isConnected();
  }
  /**
   * Connect to XRPL network
   *
   * @throws {ConnectionError} If connection fails after all retries
   */
  async connect() {
    try {
      await this.client.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
    } catch (error) {
      this.isConnected = false;
      throw new ConnectionError(`Failed to connect to ${this.nodeUrl}`, error);
    }
  }
  /**
   * Disconnect from XRPL network
   */
  async disconnect() {
    if (this.client.isConnected()) {
      await this.client.disconnect();
    }
    this.isConnected = false;
  }
  /**
   * Reconnect with exponential backoff (iterative, not recursive)
   *
   * @throws {MaxReconnectAttemptsError} If max attempts exceeded
   */
  async reconnect() {
    while (this.reconnectAttempts < this.connectionConfig.maxReconnectAttempts) {
      const delay = Math.min(
        this.connectionConfig.reconnectDelay * Math.pow(this.connectionConfig.reconnectBackoff, this.reconnectAttempts),
        3e4
        // Max 30 seconds
      );
      await sleep(delay);
      this.reconnectAttempts++;
      try {
        if (this.reconnectAttempts > 1 && this.backupUrls.length > 0) {
          this.currentUrlIndex = (this.currentUrlIndex + 1) % (this.backupUrls.length + 1);
          const url = this.currentUrlIndex === 0 ? this.nodeUrl : this.backupUrls[this.currentUrlIndex - 1];
          try {
            await this.client.disconnect();
          } catch {
          }
          this.client = new Client(url);
        }
        await this.client.connect();
        this.isConnected = true;
        this.reconnectAttempts = 0;
        return;
      } catch (error) {
        console.warn(
          `[XRPLClient] Reconnect attempt ${this.reconnectAttempts} failed:`,
          error instanceof Error ? error.message : "Unknown error"
        );
      }
    }
    throw new MaxReconnectAttemptsError(this.reconnectAttempts);
  }
  /**
   * Check server health
   *
   * @returns True if server is healthy (state is "full")
   */
  async isHealthy() {
    try {
      const response = await this.client.request({
        command: "server_state"
      });
      return response.result.state.server_state === "full";
    } catch {
      return false;
    }
  }
  /**
   * Get server information
   *
   * @returns Server information
   * @throws {XRPLClientError} If request times out
   */
  async getServerInfo() {
    const response = await withTimeout(
      this.client.request({
        command: "server_info"
      }),
      this.connectionConfig.requestTimeout,
      "server_info"
    );
    const info = response.result.info;
    return {
      server_state: info.server_state,
      validated_ledger: info.validated_ledger ?? void 0,
      complete_ledgers: info.complete_ledgers,
      peers: info.peers ?? void 0,
      validation_quorum: info.validation_quorum ?? void 0
    };
  }
  /**
   * Get account information
   *
   * @param address - Account address
   * @returns Account information
   * @throws {AccountNotFoundError} If account doesn't exist
   * @throws {XRPLClientError} If request times out
   */
  async getAccountInfo(address) {
    try {
      const response = await withTimeout(
        this.client.request({
          command: "account_info",
          account: address,
          ledger_index: "validated"
        }),
        this.connectionConfig.requestTimeout,
        "account_info"
      );
      const data = response.result.account_data;
      return {
        account: data.Account,
        balance: data.Balance,
        sequence: data.Sequence,
        ownerCount: data.OwnerCount,
        flags: data.Flags,
        previousTxnID: data.PreviousTxnID,
        previousTxnLgrSeq: data.PreviousTxnLgrSeq
      };
    } catch (error) {
      if (typeof error === "object" && error !== null && "data" in error) {
        const errorData = error;
        if (errorData.data?.error === "actNotFound") {
          throw new AccountNotFoundError(address);
        }
      }
      throw error;
    }
  }
  /**
   * Get account balance in drops
   *
   * @param address - Account address
   * @returns Balance in drops
   */
  async getBalance(address) {
    const accountInfo = await this.getAccountInfo(address);
    return accountInfo.balance;
  }
  /**
   * Get transaction information
   *
   * @param hash - Transaction hash
   * @returns Transaction response
   */
  async getTransaction(hash2) {
    return this.client.request({
      command: "tx",
      transaction: hash2
    });
  }
  /**
   * Wait for transaction validation
   *
   * @param hash - Transaction hash
   * @param options - Wait options
   * @returns Transaction result
   * @throws {TransactionTimeoutError} If transaction not validated within timeout
   */
  async waitForTransaction(hash2, options = {}) {
    const timeout = options.timeout ?? 2e4;
    const pollInterval = options.pollInterval ?? 1e3;
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      try {
        const response = await this.client.request({
          command: "tx",
          transaction: hash2
        });
        if (response.result.validated) {
          const meta = response.result.meta;
          const transactionResult = typeof meta === "object" && meta !== null && "XRPLTransactionResult" in meta ? meta.XRPLTransactionResult : "unknown";
          return {
            hash: hash2,
            resultCode: transactionResult,
            ledgerIndex: response.result.ledger_index,
            validated: true,
            meta: response.result.meta
          };
        }
      } catch (error) {
        if (typeof error === "object" && error !== null && "data" in error) {
          const errorData = error;
          if (errorData.data?.error !== "txnNotFound") {
            throw error;
          }
        }
      }
      await sleep(pollInterval);
    }
    throw new TransactionTimeoutError(hash2);
  }
  /**
   * Get current ledger index
   *
   * @returns Current validated ledger index
   */
  async getCurrentLedgerIndex() {
    const response = await this.client.request({
      command: "ledger",
      ledger_index: "validated"
    });
    return response.result.ledger_index;
  }
  /**
   * Get fee estimate for a transaction
   *
   * @returns Estimated fee in drops
   */
  async getFee() {
    const response = await this.client.request({
      command: "fee"
    });
    return response.result.drops.open_ledger_fee;
  }
  /**
   * Get account transaction history
   *
   * @param address - Account address
   * @param options - History options
   * @returns Array of transactions
   */
  async getAccountTransactions(address, options = {}) {
    const response = await this.client.request({
      command: "account_tx",
      account: address,
      ledger_index_min: options.ledgerIndexMin ?? -1,
      ledger_index_max: options.ledgerIndexMax ?? -1,
      limit: Math.min(options.limit ?? 50, 400),
      forward: options.forward ?? false
    });
    return response.result.transactions.map((tx) => tx.tx);
  }
  /**
   * Submit a signed transaction
   *
   * @param signedTx - Signed transaction blob (hex string)
   * @param options - Submit options
   * @returns Transaction result
   */
  async submitSignedTransaction(signedTx, options = {}) {
    const opts = {
      waitForValidation: true,
      timeout: 2e4,
      failHard: false,
      ...options
    };
    const response = await this.client.submit(signedTx, {
      failHard: opts.failHard
    });
    const { tx_json, engine_result, engine_result_message } = response.result;
    const hash2 = tx_json.hash ?? "unknown";
    if (engine_result !== "tesSUCCESS" && !engine_result.startsWith("ter")) {
      throw new XRPLClientError(
        `Transaction submission failed: ${engine_result} - ${engine_result_message}`,
        "TX_SUBMIT_FAILED",
        { hash: hash2, engine_result, engine_result_message }
      );
    }
    if (opts.waitForValidation) {
      return this.waitForTransaction(hash2, { timeout: opts.timeout });
    }
    return {
      hash: hash2,
      resultCode: engine_result,
      ledgerIndex: void 0,
      validated: false,
      meta: void 0
    };
  }
};
var SigningError = class extends Error {
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "SigningError";
  }
};
var SigningService = class {
  constructor(keystore, auditLogger, multiSignOrchestrator, options) {
    this.keystore = keystore;
    this.auditLogger = auditLogger;
    this.multiSignOrchestrator = multiSignOrchestrator;
    this.options = {
      strictTransactionTypes: options?.strictTransactionTypes ?? false
    };
  }
  options;
  /**
   * Sign a transaction with a wallet's private key.
   *
   * Process:
   * 1. Decode unsigned transaction blob
   * 2. Validate transaction structure
   * 3. Load wallet key from keystore (SecureBuffer)
   * 4. Create XRPL Wallet instance
   * 5. Sign transaction
   * 6. Zero key material
   * 7. Return signed blob + hash
   *
   * @param walletId - Internal wallet identifier
   * @param unsignedTx - Unsigned transaction blob (hex) or Transaction object
   * @param password - User password for key decryption
   * @param multiSign - Whether to sign for multi-signature (default: false)
   * @returns Signed transaction with hash
   *
   * @throws SigningError TRANSACTION_DECODE_ERROR - Invalid transaction format
   * @throws SigningError WALLET_NOT_FOUND - Wallet doesn't exist
   * @throws SigningError AUTHENTICATION_FAILED - Incorrect password
   * @throws SigningError SIGNING_FAILED - Cryptographic signing error
   */
  async sign(walletId, unsignedTx, password, multiSign = false) {
    let secureKey = null;
    try {
      let transaction;
      if (typeof unsignedTx === "string") {
        try {
          transaction = decode(unsignedTx);
        } catch (error) {
          throw new SigningError(
            "TRANSACTION_DECODE_ERROR",
            `Failed to decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
            { unsignedTx }
          );
        }
      } else {
        transaction = unsignedTx;
      }
      this.validateTransaction(transaction);
      const walletEntry = await this.keystore.getWallet(walletId);
      let usingRegularKey = false;
      try {
        if ("loadRegularKey" in this.keystore) {
          const keystoreWithRegularKey = this.keystore;
          const regularKey = await keystoreWithRegularKey.loadRegularKey(walletId, password);
          if (regularKey) {
            secureKey = regularKey;
            usingRegularKey = true;
          }
        }
        if (!secureKey) {
          secureKey = await this.keystore.loadKey(walletId, password);
        }
      } catch (error) {
        await this.auditLogger.log({
          event: "authentication_failed",
          wallet_id: walletId,
          wallet_address: walletEntry.address,
          context: "Authentication failed during transaction signing"
        });
        throw new SigningError(
          "AUTHENTICATION_FAILED",
          "Failed to decrypt wallet key - incorrect password or corrupted keystore",
          { wallet_id: walletId }
        );
      }
      let wallet;
      try {
        const seedString = secureKey.getBuffer().toString("utf-8");
        wallet = Wallet.fromSeed(seedString);
        if (!usingRegularKey && wallet.address !== walletEntry.address) {
          throw new Error("Wallet address mismatch - keystore corruption detected");
        }
      } catch (error) {
        throw new SigningError(
          "WALLET_CREATION_ERROR",
          `Failed to create wallet from key: ${error instanceof Error ? error.message : "Unknown error"}`,
          { wallet_id: walletId }
        );
      }
      let signedResult;
      try {
        if (multiSign) {
          signedResult = wallet.sign(transaction, true);
        } else {
          signedResult = wallet.sign(transaction);
        }
      } catch (error) {
        throw new SigningError(
          "SIGNING_FAILED",
          `Cryptographic signing failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          { wallet_id: walletId, transaction_type: transaction.TransactionType }
        );
      }
      await this.auditLogger.log({
        event: "transaction_signed",
        wallet_id: walletId,
        wallet_address: walletEntry.address,
        transaction_type: transaction.TransactionType,
        tx_hash: signedResult.hash,
        context: multiSign ? "Multi-signature signing" : "Single signature signing"
      });
      return {
        tx_blob: signedResult.tx_blob,
        hash: signedResult.hash,
        signer_address: wallet.address
      };
    } catch (error) {
      if (error instanceof SigningError && error.code !== "AUTHENTICATION_FAILED") {
        await this.auditLogger.log({
          event: "transaction_failed",
          wallet_id: walletId,
          context: `Signing failed: ${error.code} - ${error.message}`
        });
      }
      throw error;
    } finally {
      if (secureKey) {
        secureKey.dispose();
      }
    }
  }
  /**
   * Sign a transaction for multi-signature workflow.
   *
   * This is a convenience wrapper around sign() with multiSign=true.
   *
   * @param walletId - Internal wallet identifier
   * @param unsignedTx - Unsigned transaction blob or object
   * @param password - User password
   * @returns Multi-signature compatible signed transaction
   */
  async signForMultiSig(walletId, unsignedTx, password) {
    return this.sign(walletId, unsignedTx, password, true);
  }
  /**
   * Decode and validate a transaction blob without signing.
   *
   * Useful for displaying transaction details before signing.
   *
   * @param txBlob - Transaction blob (hex encoded)
   * @returns Decoded transaction object
   * @throws SigningError TRANSACTION_DECODE_ERROR
   */
  decodeTransaction(txBlob) {
    try {
      return decode(txBlob);
    } catch (error) {
      throw new SigningError(
        "TRANSACTION_DECODE_ERROR",
        `Failed to decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { tx_blob: txBlob }
      );
    }
  }
  /**
   * Encode a transaction object to blob format.
   *
   * @param transaction - Transaction object
   * @returns Hex-encoded transaction blob
   * @throws SigningError TRANSACTION_ENCODE_ERROR
   */
  encodeTransaction(transaction) {
    try {
      return encode(transaction);
    } catch (error) {
      throw new SigningError(
        "TRANSACTION_ENCODE_ERROR",
        `Failed to encode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { transaction }
      );
    }
  }
  /**
   * Validate transaction structure before signing.
   *
   * Checks:
   * - Required fields present
   * - Account address is valid
   * - TransactionType is recognized
   *
   * @param transaction - Transaction to validate
   * @throws SigningError INVALID_TRANSACTION
   */
  validateTransaction(transaction) {
    if (!transaction.TransactionType) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        "Transaction missing required field: TransactionType"
      );
    }
    if (!transaction.Account) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        "Transaction missing required field: Account"
      );
    }
    if (!transaction.Account.startsWith("r") || transaction.Account.length < 25) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        `Invalid Account address format: ${transaction.Account}`
      );
    }
    const validTypes = [
      "Payment",
      "OfferCreate",
      "OfferCancel",
      "TrustSet",
      "AccountSet",
      "SetRegularKey",
      "SignerListSet",
      "EscrowCreate",
      "EscrowFinish",
      "EscrowCancel",
      "PaymentChannelCreate",
      "PaymentChannelClaim",
      "PaymentChannelFund",
      "CheckCreate",
      "CheckCash",
      "CheckCancel",
      "NFTokenMint",
      "NFTokenBurn",
      "NFTokenCreateOffer",
      "NFTokenCancelOffer",
      "NFTokenAcceptOffer",
      "AMMCreate",
      "AMMDeposit",
      "AMMWithdraw",
      "AMMVote",
      "AMMBid",
      "AMMDelete",
      "DepositPreauth",
      "AccountDelete"
    ];
    if (!validTypes.includes(transaction.TransactionType)) {
      if (this.options.strictTransactionTypes) {
        throw new SigningError(
          "UNKNOWN_TRANSACTION_TYPE",
          `Unknown transaction type: ${transaction.TransactionType}. Enable experimental transaction support by setting strictTransactionTypes: false`,
          { transaction_type: transaction.TransactionType }
        );
      } else {
        console.warn(
          `[SigningService] Unknown TransactionType: ${transaction.TransactionType}. This may be an experimental or new transaction type.`
        );
      }
    }
  }
};

// src/signing/multisig.ts
__toESM(require_dist2(), 1);
var MultiSignError = class extends Error {
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "MultiSignError";
  }
};
var MultiSignOrchestrator = class {
  constructor(xrplClient, store, notificationService, auditLogger) {
    this.xrplClient = xrplClient;
    this.store = store;
    this.notificationService = notificationService;
    this.auditLogger = auditLogger;
  }
  /**
   * Initiate a new multi-signature request.
   *
   * Creates a pending request, notifies approvers, and returns
   * the request ID for status tracking.
   *
   * @param walletId - Internal wallet identifier
   * @param walletAddress - XRPL address of the account
   * @param unsignedTx - Unsigned transaction blob (hex)
   * @param signerConfig - SignerList configuration for this wallet
   * @param context - Human-readable context for audit
   * @returns Multi-signature request with pending status
   *
   * @throws MultiSignError WALLET_NOT_FOUND - Wallet doesn't exist
   * @throws MultiSignError SIGNERLIST_NOT_CONFIGURED - Wallet has no SignerList
   * @throws MultiSignError INVALID_TRANSACTION - Cannot decode transaction
   */
  async initiate(walletId, walletAddress, unsignedTx, signerConfig, context) {
    if (!signerConfig || signerConfig.signers.length === 0) {
      throw new MultiSignError(
        "SIGNERLIST_NOT_CONFIGURED",
        "Wallet does not have multi-signature configured"
      );
    }
    let decodedTx;
    try {
      const { decode: decode7 } = await import('xrpl');
      decodedTx = decode7(unsignedTx);
    } catch (error) {
      throw new MultiSignError(
        "INVALID_TRANSACTION",
        `Cannot decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { unsigned_tx: unsignedTx }
      );
    }
    const requestId = randomUUID();
    const now = /* @__PURE__ */ new Date();
    const timeoutSeconds = signerConfig.timeout_seconds || 86400;
    const expiresAt = new Date(now.getTime() + timeoutSeconds * 1e3);
    const amountDrops = this.extractAmount(decodedTx);
    const destination = this.extractDestination(decodedTx);
    const request = {
      id: requestId,
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction: {
        type: decodedTx.TransactionType,
        ...amountDrops !== void 0 && { amount_drops: amountDrops },
        ...destination !== void 0 && { destination },
        unsigned_blob: unsignedTx,
        decoded: decodedTx
      },
      signers: signerConfig.signers.map((s) => ({
        address: s.address,
        role: s.role,
        weight: s.weight,
        signed: false
      })),
      quorum: {
        required: signerConfig.quorum,
        collected: 0,
        met: false
      },
      status: "pending",
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      ...context && { context },
      notifications_sent: []
    };
    await this.store.create(request);
    await this.auditLogger.log({
      event: "approval_requested",
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction_type: decodedTx.TransactionType,
      context: context || `Multi-sign requested: ${signerConfig.quorum} of ${signerConfig.signers.length} signatures`
    });
    this.notifySigners(request, "created").catch(
      (err) => console.error("Failed to send notifications:", err)
    );
    return request;
  }
  /**
   * Add a signature from a human approver.
   *
   * Validates the signature, stores it, and checks if quorum is met.
   * Updates request status and notifies if ready for completion.
   *
   * @param requestId - Multi-sign request UUID
   * @param signature - Signed transaction from approver
   * @param signerAddress - Address of the signer (for validation)
   * @returns Updated request with new signature and quorum status
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_EXPIRED - Request timeout exceeded
   * @throws MultiSignError REQUEST_COMPLETED - Already finalized
   * @throws MultiSignError INVALID_SIGNER - Address not in SignerList
   * @throws MultiSignError DUPLICATE_SIGNATURE - Signer already signed
   * @throws MultiSignError SIGNATURE_INVALID - Cryptographic verification failed
   */
  async addSignature(requestId, signature, signerAddress) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (new Date(request.expires_at) < /* @__PURE__ */ new Date()) {
      throw new MultiSignError("REQUEST_EXPIRED", "Multi-sign request has expired");
    }
    if (request.status === "completed") {
      throw new MultiSignError("REQUEST_COMPLETED", "Request already completed");
    }
    if (request.status === "rejected") {
      throw new MultiSignError("REQUEST_REJECTED", "Request has been rejected");
    }
    const signer = request.signers.find((s) => s.address === signerAddress);
    if (!signer) {
      throw new MultiSignError(
        "INVALID_SIGNER",
        `Address ${signerAddress} is not in the SignerList`,
        { signer_address: signerAddress, request_id: requestId }
      );
    }
    if (signer.signed) {
      throw new MultiSignError(
        "DUPLICATE_SIGNATURE",
        `Signer ${signerAddress} has already signed this request`
      );
    }
    const validationResult = this.validateSignature(
      signature,
      signerAddress,
      request.transaction.unsigned_blob
    );
    if (!validationResult.valid) {
      throw new MultiSignError(
        "SIGNATURE_INVALID",
        `Signature validation failed: ${validationResult.reason}`,
        { signer_address: signerAddress, request_id: requestId }
      );
    }
    signer.signed = true;
    signer.signature = signature;
    signer.signed_at = (/* @__PURE__ */ new Date()).toISOString();
    const collectedWeight = request.signers.filter((s) => s.signed).reduce((sum, s) => sum + s.weight, 0);
    request.quorum.collected = collectedWeight;
    request.quorum.met = collectedWeight >= request.quorum.required;
    if (request.quorum.met) {
      request.status = "approved";
    }
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_granted",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Signature added by ${signerAddress} (${signer.role}). Quorum: ${collectedWeight}/${request.quorum.required}`
    });
    if (request.quorum.met) {
      this.notifySigners(request, "signature_added").catch(
        (err) => console.error("Failed to send notifications:", err)
      );
    }
    return request;
  }
  /**
   * Complete multi-signature and submit to XRPL.
   *
   * Verifies quorum is met, adds agent signature if needed,
   * assembles the final multi-signed transaction, and submits.
   *
   * @param requestId - Multi-sign request UUID
   * @param agentWallet - Agent's wallet (for final signature if needed)
   * @returns Completed transaction with hash
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_EXPIRED - Request timeout exceeded
   * @throws MultiSignError QUORUM_NOT_MET - Insufficient signatures
   * @throws MultiSignError SUBMISSION_FAILED - XRPL submission error
   */
  async complete(requestId, agentWallet) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (new Date(request.expires_at) < /* @__PURE__ */ new Date()) {
      throw new MultiSignError("REQUEST_EXPIRED", "Multi-sign request has expired");
    }
    const agentSigner = request.signers.find((s) => s.role === "agent");
    if (agentSigner && !agentSigner.signed && agentWallet) {
      const agentSig = agentWallet.sign(request.transaction.decoded, true);
      agentSigner.signed = true;
      agentSigner.signature = agentSig.tx_blob;
      agentSigner.signed_at = (/* @__PURE__ */ new Date()).toISOString();
      const collectedWeight = request.signers.filter((s) => s.signed).reduce((sum, s) => sum + s.weight, 0);
      request.quorum.collected = collectedWeight;
      request.quorum.met = collectedWeight >= request.quorum.required;
    }
    if (!request.quorum.met) {
      throw new MultiSignError(
        "QUORUM_NOT_MET",
        `Collected weight ${request.quorum.collected} < required ${request.quorum.required}`
      );
    }
    const signatures = request.signers.filter((s) => s.signed && s.signature).map((s) => s.signature);
    if (signatures.length === 0) {
      throw new MultiSignError("NO_SIGNATURES", "No signatures collected");
    }
    const multiSignedTx = multisign(signatures);
    let txHash;
    try {
      const response = await this.xrplClient.submitAndWait(multiSignedTx, {
        autofill: false,
        failHard: true
      });
      const meta = response.result.meta;
      const result = typeof meta === "object" && meta !== null && "TransactionResult" in meta ? meta.TransactionResult : "UNKNOWN";
      txHash = response.result.hash;
      if (result !== "tesSUCCESS") {
        throw new Error(`Transaction failed with result: ${result}`);
      }
    } catch (error) {
      throw new MultiSignError(
        "SUBMISSION_FAILED",
        `Failed to submit multi-signed transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { request_id: requestId }
      );
    }
    request.status = "completed";
    request.completed_at = (/* @__PURE__ */ new Date()).toISOString();
    request.tx_hash = txHash;
    await this.store.update(request);
    await this.auditLogger.log({
      event: "transaction_submitted",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      transaction_type: request.transaction.type,
      tx_hash: txHash,
      context: `Multi-signed transaction completed with ${signatures.length} signatures`
    });
    return {
      request_id: requestId,
      signed_tx: multiSignedTx,
      tx_hash: txHash,
      final_quorum: request.quorum.collected,
      signers: request.signers.filter((s) => s.signed).map((s) => s.address),
      submitted_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  /**
   * Reject a pending multi-sign request.
   *
   * Human approver explicitly rejects the transaction.
   * Discards all collected signatures and logs rejection.
   *
   * @param requestId - Multi-sign request UUID
   * @param rejectingAddress - Address of the rejecting approver
   * @param reason - Human-readable rejection reason
   * @returns Updated request with rejected status
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_COMPLETED - Already finalized
   * @throws MultiSignError UNAUTHORIZED_REJECTOR - Not an authorized signer
   */
  async reject(requestId, rejectingAddress, reason) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (request.status === "completed") {
      throw new MultiSignError("REQUEST_COMPLETED", "Cannot reject completed request");
    }
    const rejector = request.signers.find((s) => s.address === rejectingAddress);
    if (!rejector) {
      throw new MultiSignError(
        "UNAUTHORIZED_REJECTOR",
        `Address ${rejectingAddress} is not an authorized signer`
      );
    }
    request.status = "rejected";
    request.rejection = {
      rejecting_address: rejectingAddress,
      reason,
      rejected_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_denied",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Rejected by ${rejectingAddress}: ${reason}`
    });
    return request;
  }
  /**
   * Get current status of a multi-sign request.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Current request state with signatures and quorum
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   */
  async getStatus(requestId) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    return request;
  }
  /**
   * List all pending multi-sign requests for a wallet.
   *
   * @param walletId - Internal wallet identifier
   * @param includeExpired - Include expired requests (default: false)
   * @returns Array of pending requests sorted by creation time
   */
  async listPending(walletId, includeExpired = false) {
    return this.store.listByWallet(walletId, false);
  }
  /**
   * Cancel an expired request.
   *
   * Automated cleanup of requests that exceeded timeout.
   * Called by scheduled task, not directly by users.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Updated request with expired status
   *
   * @internal
   */
  async expire(requestId) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    request.status = "expired";
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_expired",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Request expired with ${request.signers.filter((s) => s.signed).length}/${request.quorum.required} signatures`
    });
    return request;
  }
  // ==========================================================================
  // SIGNATURE VALIDATION
  // ==========================================================================
  /**
   * Validate a multi-signature cryptographically.
   *
   * Verifies that:
   * 1. The signature blob is a valid signed transaction
   * 2. The signer in the blob matches the claimed signer address
   * 3. The signature covers the expected unsigned transaction
   *
   * @param signatureBlob - Signed transaction blob from the signer
   * @param expectedSigner - Expected signer's XRPL address
   * @param unsignedBlob - Original unsigned transaction blob
   * @returns Validation result with reason if invalid
   */
  validateSignature(signatureBlob, expectedSigner, unsignedBlob) {
    try {
      let signedTx;
      try {
        signedTx = decode(signatureBlob);
      } catch (error) {
        return { valid: false, reason: "Invalid transaction blob format" };
      }
      if (!signedTx.Signers || !Array.isArray(signedTx.Signers)) {
        if (!signedTx.TxnSignature) {
          return { valid: false, reason: "No signature found in transaction" };
        }
        if (signedTx.SigningPubKey) {
          try {
            const signerWallet = new Wallet(signedTx.SigningPubKey, "0".repeat(64));
            if (signerWallet.classicAddress !== expectedSigner) {
              return {
                valid: false,
                reason: `Signer mismatch: expected ${expectedSigner}, got ${signerWallet.classicAddress}`
              };
            }
          } catch {
            return { valid: false, reason: "Could not derive address from signing public key" };
          }
        }
        return { valid: true };
      }
      const signerEntry = signedTx.Signers.find(
        (s) => s.Signer?.Account === expectedSigner
      );
      if (!signerEntry) {
        return {
          valid: false,
          reason: `No signature from expected signer ${expectedSigner}`
        };
      }
      if (!signerEntry.Signer?.TxnSignature || !signerEntry.Signer?.SigningPubKey) {
        return { valid: false, reason: "Incomplete signer entry" };
      }
      try {
        const signerWallet = new Wallet(signerEntry.Signer.SigningPubKey, "0".repeat(64));
        if (signerWallet.classicAddress !== expectedSigner) {
          return {
            valid: false,
            reason: `Public key does not match signer address`
          };
        }
      } catch {
        return { valid: false, reason: "Invalid signing public key" };
      }
      let unsignedTx;
      try {
        unsignedTx = decode(unsignedBlob);
      } catch {
        return { valid: true };
      }
      const criticalFields = ["TransactionType", "Account", "Destination", "Amount", "Fee", "Sequence"];
      for (const field of criticalFields) {
        if (unsignedTx[field] !== void 0 && signedTx[field] !== unsignedTx[field]) {
          if ((field === "Amount" || field === "Fee") && String(unsignedTx[field]) === String(signedTx[field])) {
            continue;
          }
          return {
            valid: false,
            reason: `Transaction field mismatch: ${field}`
          };
        }
      }
      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        reason: `Validation error: ${error instanceof Error ? error.message : "Unknown error"}`
      };
    }
  }
  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================
  extractAmount(tx) {
    if ("Amount" in tx && typeof tx.Amount === "string") {
      return tx.Amount;
    }
    return void 0;
  }
  extractDestination(tx) {
    if ("Destination" in tx && typeof tx.Destination === "string") {
      return tx.Destination;
    }
    return void 0;
  }
  async notifySigners(request, type) {
    console.log(`[MultiSign] Notification: ${type} for request ${request.id}`);
  }
};

// src/utils/env.ts
var MissingEnvironmentVariableError = class extends Error {
  constructor(variableName, description) {
    const message = description ? `Required environment variable ${variableName} is not set: ${description}` : `Required environment variable ${variableName} is not set`;
    super(message);
    this.variableName = variableName;
    this.description = description;
    this.name = "MissingEnvironmentVariableError";
  }
};
function getRequiredEnv(name, description) {
  const value = process.env[name];
  if (value === void 0 || value === "") {
    throw new MissingEnvironmentVariableError(name, description);
  }
  return value;
}
function getWalletPassword() {
  return getRequiredEnv(
    "XRPL_WALLET_PASSWORD",
    "Master encryption password for wallet keystore. Set this environment variable to a strong password."
  );
}

// src/tools/wallet-create.ts
async function handleWalletCreate(context, input) {
  const { keystore, policyEngine, auditLogger } = context;
  await policyEngine.setPolicy(input.policy);
  const password = getWalletPassword();
  const walletEntry = await keystore.createWallet(
    input.network,
    {
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version
    },
    {
      ...input.wallet_name ? { name: input.wallet_name } : {},
      password,
      algorithm: "ed25519"
      // Recommended for XRPL
    }
  );
  const backup = await keystore.exportBackup(
    walletEntry.walletId,
    password,
    "encrypted-json"
  );
  await auditLogger.log({
    event: "wallet_created",
    wallet_id: walletEntry.walletId,
    wallet_address: walletEntry.address,
    context: `Policy: ${input.policy.policy_id}`
  });
  return {
    address: walletEntry.address,
    regular_key_public: walletEntry.publicKey,
    master_key_backup: JSON.stringify(backup),
    policy_id: input.policy.policy_id,
    wallet_id: walletEntry.walletId,
    network: input.network,
    created_at: walletEntry.createdAt
  };
}
async function handleWalletSign(context, input) {
  const { keystore, policyEngine, signingService, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const decoded = decode(input.unsigned_tx);
  const transactionType = decoded["TransactionType"];
  const destination = "Destination" in decoded ? decoded["Destination"] : void 0;
  const amountField = "Amount" in decoded ? decoded["Amount"] : void 0;
  const amountDrops = typeof amountField === "string" ? amountField : void 0;
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: transactionType,
      ...destination ? { destination } : {},
      ...amountDrops ? { amount_drops: amountDrops } : {}
    }
  );
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (policyResult.tier === 4) {
    await auditLogger.log({
      event: "policy_violation",
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: transactionType,
      // Cast to TransactionType enum
      tier: 4,
      policy_decision: "denied",
      ...input.context ? { context: input.context } : {}
    });
    return {
      status: "rejected",
      reason: policyResult.violations?.join("; ") || "Transaction violates policy",
      policy_tier: 4
    };
  }
  if (policyResult.tier === 2 || policyResult.tier === 3) {
    const approvalId = `approval_${Date.now()}_${wallet.walletId}`;
    await auditLogger.log({
      event: "approval_requested",
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: transactionType,
      // Cast to TransactionType enum
      tier: policyResult.tier,
      policy_decision: "pending",
      ...input.context ? { context: input.context } : {}
    });
    return {
      status: "pending_approval",
      approval_id: approvalId,
      reason: policyResult.tier === 2 ? "exceeds_autonomous_limit" : "requires_cosign",
      expires_at: new Date(Date.now() + 3e5).toISOString(),
      // 5 minutes
      policy_tier: policyResult.tier
    };
  }
  const password = getWalletPassword();
  const signed = await signingService.sign(
    wallet.walletId,
    input.unsigned_tx,
    password
  );
  await auditLogger.log({
    event: "transaction_signed",
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    transaction_type: transactionType,
    // Cast to TransactionType enum
    tx_hash: signed.hash,
    tier: 1,
    policy_decision: "allowed",
    ...input.context ? { context: input.context } : {}
  });
  const limitState = policyEngine.getLimitState();
  policyEngine.getPolicyInfo();
  const dailyTransactionsUsed = limitState.daily.transactionCount;
  const hourlyTransactionsUsed = limitState.hourly.transactions.length;
  const dailyVolumeUsedXrp = limitState.daily.totalVolumeXrp;
  const maxTxPerDay = 100;
  const maxTxPerHour = 10;
  const maxDailyVolumeXrp = 1e4;
  return {
    status: "approved",
    signed_tx: signed.tx_blob,
    tx_hash: signed.hash,
    policy_tier: 1,
    limits_after: {
      daily_remaining_drops: String(Math.max(0, (maxDailyVolumeXrp - dailyVolumeUsedXrp) * 1e6)),
      hourly_tx_remaining: Math.max(0, maxTxPerHour - hourlyTransactionsUsed),
      daily_tx_remaining: Math.max(0, maxTxPerDay - dailyTransactionsUsed)
    },
    signed_at: timestamp
  };
}
function sleep2(ms) {
  return new Promise((resolve2) => setTimeout(resolve2, ms));
}
async function handleWalletBalance(context, input) {
  const { keystore, xrplClient } = context;
  if (input.wait_after_tx && input.wait_after_tx > 0) {
    await sleep2(input.wait_after_tx);
  }
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
  const currentLedgerIndex = await xrplClient.getCurrentLedgerIndex();
  let baseReserve = BigInt("10000000");
  let ownerReserve = BigInt("2000000");
  try {
    const serverInfo = await xrplClient.getServerInfo();
    if (serverInfo.validated_ledger) {
      baseReserve = BigInt(Math.floor(serverInfo.validated_ledger.reserve_base_xrp * 1e6));
      ownerReserve = BigInt(Math.floor(serverInfo.validated_ledger.reserve_inc_xrp * 1e6));
    }
  } catch (error) {
    console.warn("Could not fetch server info for reserves, using defaults");
  }
  const ownerCount = BigInt(accountInfo.ownerCount || 0);
  const totalReserve = baseReserve + ownerReserve * ownerCount;
  const balance = BigInt(accountInfo.balance);
  const available = balance > totalReserve ? balance - totalReserve : BigInt(0);
  return {
    address: input.wallet_address,
    balance_drops: balance.toString(),
    balance_xrp: String(dropsToXrp$1(balance.toString())),
    // Ensure string type
    reserve_drops: totalReserve.toString(),
    available_drops: available.toString(),
    sequence: accountInfo.sequence,
    // Keep as number per schema
    regular_key_set: !!accountInfo.regularKey,
    signer_list: null,
    // SignerList would require separate account_objects query
    policy_id: wallet.policyId,
    network: wallet.network,
    ledger_index: currentLedgerIndex,
    queried_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
async function handleWalletPolicyCheck(context, input) {
  const { keystore, policyEngine } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const decoded = decode(input.unsigned_tx);
  const transactionType = decoded["TransactionType"];
  const destinationField = "Destination" in decoded ? decoded["Destination"] : void 0;
  const destination = typeof destinationField === "string" ? destinationField : void 0;
  const amountField = "Amount" in decoded ? decoded["Amount"] : void 0;
  const amountDrops = typeof amountField === "string" ? amountField : void 0;
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: transactionType,
      ...destination ? { destination } : {},
      ...amountDrops ? { amount_drops: amountDrops } : {}
    }
  );
  const limitState = policyEngine.getLimitState();
  const maxTxPerHour = 50;
  const maxTxPerDay = 200;
  const maxDailyVolumeXrp = 1e4;
  const limits = {
    daily_volume_used_drops: String(Math.floor(limitState.daily.totalVolumeXrp * 1e6)),
    daily_volume_limit_drops: String(maxDailyVolumeXrp * 1e6),
    hourly_tx_used: limitState.hourly.transactions.length,
    hourly_tx_limit: maxTxPerHour,
    daily_tx_used: limitState.daily.transactionCount,
    daily_tx_limit: maxTxPerDay
  };
  return {
    would_approve: policyResult.tier === 1,
    tier: policyResult.tier,
    warnings: policyResult.warnings || [],
    violations: policyResult.violations || [],
    limits,
    transaction_details: {
      type: transactionType,
      // Cast to match expected transaction type enum
      ...destination ? { destination } : {},
      ...amountDrops ? { amount_drops: amountDrops } : {}
    }
  };
}
async function handleWalletRotate(context, input) {
  const { keystore, signingService, xrplClient, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const newRegularKeyWallet = Wallet.generate();
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
  const fee = await xrplClient.getFee();
  const setRegularKeyTx = {
    TransactionType: "SetRegularKey",
    Account: input.wallet_address,
    RegularKey: newRegularKeyWallet.classicAddress,
    Sequence: accountInfo.sequence,
    Fee: fee
  };
  const password = getWalletPassword();
  const signed = await signingService.sign(wallet.walletId, setRegularKeyTx, password);
  const result = await xrplClient.submitSignedTransaction(signed.tx_blob, {
    waitForValidation: true,
    timeout: 3e4
    // 30 seconds
  });
  if (!result.validated) {
    throw new Error(`SetRegularKey transaction not validated: ${result.resultCode}`);
  }
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if ("storeRegularKey" in keystore) {
    const keystoreWithRegularKey = keystore;
    await keystoreWithRegularKey.storeRegularKey(
      wallet.walletId,
      newRegularKeyWallet.seed,
      newRegularKeyWallet.classicAddress,
      password
    );
  }
  await keystore.updateMetadata(wallet.walletId, {
    hasRegularKey: true,
    lastUsedAt: timestamp,
    customData: {
      ...wallet.customData,
      regularKeyAddress: newRegularKeyWallet.classicAddress,
      regularKeyPublic: newRegularKeyWallet.publicKey,
      lastRotatedAt: timestamp,
      rotationReason: input.reason || "Manual rotation",
      rotationTxHash: result.hash
    }
  });
  await auditLogger.log({
    event: "key_rotated",
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: JSON.stringify({
      reason: input.reason || "Manual rotation",
      new_regular_key_address: newRegularKeyWallet.classicAddress,
      rotation_tx_hash: result.hash
    })
  });
  return {
    status: "rotated",
    new_regular_key_public: newRegularKeyWallet.publicKey,
    old_key_disabled: true,
    rotation_tx_hash: result.hash,
    rotated_at: timestamp
  };
}

// src/tools/wallet-list.ts
async function handleWalletList(context, input) {
  const { keystore } = context;
  const walletSummaries = await keystore.listWallets(input.network);
  const wallets = walletSummaries.map((w) => ({
    wallet_id: w.walletId,
    address: w.address,
    name: w.name,
    network: w.network,
    policy_id: w.policyId,
    created_at: w.createdAt
  }));
  return {
    wallets,
    total: wallets.length
  };
}

// src/tools/wallet-history.ts
async function handleWalletHistory(context, input) {
  const { keystore, xrplClient } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const rawTransactions = await xrplClient.getAccountTransactions(
    input.wallet_address,
    {
      limit: input.limit || 20
    }
  );
  const transactions = rawTransactions.map((tx) => {
    const txData = tx.tx || tx;
    const meta = tx.meta || {};
    const resultCode = typeof meta === "object" && meta.TransactionResult ? meta.TransactionResult : "unknown";
    return {
      hash: txData.hash || tx.hash || "",
      type: txData.TransactionType || "Unknown",
      amount_drops: "Amount" in txData && typeof txData.Amount === "string" ? txData.Amount : void 0,
      destination: "Destination" in txData ? txData.Destination : void 0,
      timestamp: txData.date ? new Date((txData.date + 946684800) * 1e3).toISOString() : (/* @__PURE__ */ new Date()).toISOString(),
      policy_tier: 1,
      // Historical transactions don't have policy tier info
      context: void 0,
      // Would need to cross-reference with audit log
      ledger_index: txData.ledger_index || tx.ledger_index || 0,
      success: resultCode === "tesSUCCESS"
    };
  });
  return {
    address: input.wallet_address,
    transactions,
    marker: void 0,
    // Pagination marker if available
    has_more: transactions.length >= (input.limit || 20)
  };
}
var FAUCET_CONFIG2 = {
  /** Maximum retries for account confirmation */
  maxRetries: 15,
  /** Delay between retries in milliseconds */
  retryDelayMs: 2e3,
  /** Initial wait after faucet request before first check */
  initialWaitMs: 3e3
};
function sleep3(ms) {
  return new Promise((resolve2) => setTimeout(resolve2, ms));
}
async function handleWalletFund(context, input) {
  const { auditLogger } = context;
  const waitForConfirmation = input.wait_for_confirmation ?? true;
  const faucetUrl = getFaucetUrl(input.network);
  if (!faucetUrl) {
    return {
      status: "failed",
      error: `No faucet available for network: ${input.network}`
    };
  }
  const wsUrl = getWebSocketUrl(input.network);
  const client = new Client(wsUrl);
  try {
    await client.connect();
    await auditLogger.log({
      event: "wallet_created",
      // Using existing event type for audit
      wallet_address: input.wallet_address,
      context: `Faucet funding requested for ${input.network}`
    });
    let fundResult;
    try {
      const faucetResponse = await fetch(faucetUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          destination: input.wallet_address
        })
      });
      if (!faucetResponse.ok) {
        const errorText = await faucetResponse.text();
        throw new Error(`Faucet request failed: ${faucetResponse.status} - ${errorText}`);
      }
      const faucetData = await faucetResponse.json();
      fundResult = {
        balance: faucetData.balance ?? faucetData.amount ?? 0
      };
    } catch (faucetError) {
      await client.disconnect();
      return {
        status: "failed",
        error: faucetError instanceof Error ? faucetError.message : "Faucet request failed",
        faucet_url: faucetUrl
      };
    }
    if (!waitForConfirmation) {
      await client.disconnect();
      return {
        status: "pending",
        account_ready: false,
        faucet_url: faucetUrl,
        message: "Funding submitted. Account may take 5-20 seconds to appear on validated ledger."
      };
    }
    await sleep3(FAUCET_CONFIG2.initialWaitMs);
    let accountReady = false;
    let finalBalance = "0";
    let ledgerIndex;
    for (let attempt = 0; attempt < FAUCET_CONFIG2.maxRetries; attempt++) {
      try {
        const accountInfo = await client.request({
          command: "account_info",
          account: input.wallet_address,
          ledger_index: "validated"
        });
        finalBalance = accountInfo.result.account_data.Balance;
        ledgerIndex = accountInfo.result.ledger_index;
        accountReady = true;
        break;
      } catch (error) {
        const errorData = error;
        if (errorData.data?.error === "actNotFound") {
          await sleep3(FAUCET_CONFIG2.retryDelayMs);
          continue;
        }
        console.warn(`[wallet_fund] Attempt ${attempt + 1} failed:`, error);
        await sleep3(FAUCET_CONFIG2.retryDelayMs);
      }
    }
    await client.disconnect();
    if (!accountReady) {
      return {
        status: "pending",
        account_ready: false,
        faucet_url: faucetUrl,
        message: `Account not confirmed after ${FAUCET_CONFIG2.maxRetries * FAUCET_CONFIG2.retryDelayMs / 1e3}s. It may still appear later.`
      };
    }
    return {
      status: "funded",
      amount_drops: finalBalance,
      initial_balance_drops: finalBalance,
      new_balance_drops: finalBalance,
      // Deprecated but kept for compatibility
      account_ready: true,
      ledger_index: ledgerIndex,
      faucet_url: faucetUrl
    };
  } catch (error) {
    try {
      if (client.isConnected()) {
        await client.disconnect();
      }
    } catch {
    }
    return {
      status: "failed",
      error: error instanceof Error ? error.message : "Unknown faucet error",
      faucet_url: faucetUrl
    };
  }
}

// src/tools/policy-set.ts
async function handlePolicySet(context, input) {
  const { keystore, policyEngine, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const previousPolicyId = wallet.policyId;
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (!input.policy.policy_id) {
    throw new Error("Policy must have a policy_id");
  }
  if (!input.policy.policy_version) {
    throw new Error("Policy must have a policy_version");
  }
  const changeAnalysis = analyzePolicyChange(previousPolicyId, input.policy);
  console.log(
    `[PolicySet] Policy update requested for wallet ${wallet.walletId}: ${previousPolicyId} -> ${input.policy.policy_id} v${input.policy.policy_version}`
  );
  await keystore.updateMetadata(wallet.walletId, {
    customData: {
      ...wallet.customData,
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version,
      policyUpdatedAt: timestamp,
      policyUpdateReason: input.reason,
      previousPolicyId
    }
  });
  await auditLogger.log({
    event: "policy_updated",
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: JSON.stringify({
      reason: input.reason,
      previous_policy_id: previousPolicyId,
      new_policy_id: input.policy.policy_id,
      new_policy_version: input.policy.policy_version,
      change_analysis: changeAnalysis
    })
  });
  return {
    status: "applied",
    previous_policy_id: previousPolicyId,
    new_policy_id: input.policy.policy_id,
    applied_at: timestamp
    // Note: The policy metadata is updated, but the PolicyEngine won't use
    // the new policy until the server is restarted (immutability requirement).
  };
}
function analyzePolicyChange(previousPolicyId, newPolicy) {
  const changes = [];
  changes.push(`Policy ID changed from "${previousPolicyId}" to "${newPolicy.policy_id}"`);
  changes.push(`Policy version: ${newPolicy.policy_version}`);
  let riskLevel = "low";
  const maxAmountDrops = BigInt(newPolicy.limits.max_amount_per_tx_drops);
  const maxDailyDrops = BigInt(newPolicy.limits.max_daily_volume_drops);
  if (maxAmountDrops > BigInt("10000000000")) {
    changes.push(`High per-transaction limit: ${Number(maxAmountDrops) / 1e6} XRP`);
    riskLevel = "high";
  }
  if (maxDailyDrops > BigInt("100000000000")) {
    changes.push(`High daily volume limit: ${Number(maxDailyDrops) / 1e6} XRP`);
    riskLevel = "high";
  }
  if (newPolicy.destinations.mode === "open") {
    changes.push('Destination mode is "open" - any destination allowed');
    if (riskLevel !== "high") riskLevel = "medium";
  }
  if (newPolicy.transaction_types.allowed.length > 10) {
    changes.push(`Many transaction types allowed: ${newPolicy.transaction_types.allowed.length}`);
    if (riskLevel !== "high") riskLevel = "medium";
  }
  return {
    risk_level: riskLevel,
    changes
  };
}
function extractTransactionMetadata(decoded) {
  const txType = decoded.TransactionType;
  const sequenceUsed = typeof decoded.Sequence === "number" ? decoded.Sequence : void 0;
  let escrowReference;
  if (txType === "EscrowCreate" && sequenceUsed !== void 0) {
    const owner = decoded.Account;
    if (owner) {
      escrowReference = {
        owner,
        sequence: sequenceUsed
      };
    }
  }
  return { txType, sequenceUsed, escrowReference };
}
async function handleTxSubmit(context, input) {
  const { xrplClient, auditLogger } = context;
  const submittedAt = (/* @__PURE__ */ new Date()).toISOString();
  let txType;
  let sequenceUsed;
  let escrowReference;
  try {
    const decoded = decode(input.signed_tx);
    const metadata = extractTransactionMetadata(decoded);
    txType = metadata.txType;
    sequenceUsed = metadata.sequenceUsed;
    escrowReference = metadata.escrowReference;
  } catch (decodeError) {
    console.warn("[tx_submit] Could not decode transaction for metadata:", decodeError);
  }
  const result = await xrplClient.submitSignedTransaction(input.signed_tx, {
    waitForValidation: input.wait_for_validation ?? true
  });
  await auditLogger.log({
    event: "transaction_submitted",
    tx_hash: result.hash,
    policy_decision: result.validated ? "allowed" : "pending",
    transaction_type: txType,
    context: escrowReference ? `EscrowCreate: owner=${escrowReference.owner}, sequence=${escrowReference.sequence}` : void 0
  });
  const response = {
    tx_hash: result.hash,
    result: {
      result_code: result.resultCode,
      result_message: result.resultCode,
      // resultCode serves as message
      success: result.resultCode === "tesSUCCESS"
    },
    ledger_index: result.ledgerIndex,
    submitted_at: submittedAt,
    validated_at: result.validated ? (/* @__PURE__ */ new Date()).toISOString() : void 0,
    tx_type: txType,
    sequence_used: sequenceUsed
  };
  if (escrowReference && result.resultCode === "tesSUCCESS") {
    response.escrow_reference = escrowReference;
  }
  return response;
}
async function handleTxDecode(_context, input) {
  const decoded = decode(input.tx_blob);
  const isSigned = "TxnSignature" in decoded || "Signers" in decoded;
  const signingPubKeyField = "SigningPubKey" in decoded ? decoded["SigningPubKey"] : void 0;
  const signingPublicKey = typeof signingPubKeyField === "string" ? signingPubKeyField : void 0;
  let hash2;
  if (isSigned) {
    try {
      hash2 = hashes.hashSignedTx(input.tx_blob);
    } catch {
      hash2 = void 0;
    }
  }
  return {
    transaction: decoded,
    // Type assertion - decoded tx matches schema
    hash: hash2,
    is_signed: isSigned,
    signing_public_key: signingPublicKey
  };
}
var TOOLS = [
  {
    name: "wallet_create",
    description: "Create a new XRPL wallet with policy controls. Generates keys locally with encrypted storage.",
    inputSchema: {
      type: "object",
      properties: {
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] },
        policy: { type: "object" },
        wallet_name: { type: "string" },
        funding_source: { type: "string" },
        initial_funding_drops: { type: "string" }
      },
      required: ["network", "policy"]
    }
  },
  {
    name: "wallet_sign",
    description: "Sign a transaction with policy enforcement. Returns signed blob, pending approval, or rejection.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        unsigned_tx: { type: "string" },
        context: { type: "string" }
      },
      required: ["wallet_address", "unsigned_tx"]
    }
  },
  {
    name: "wallet_balance",
    description: "Query wallet balance, reserves, and status. Returns current state from XRPL with ledger_index for verification.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        wait_after_tx: { type: "number", minimum: 0, maximum: 3e4, description: "Wait time in ms before querying (for post-transaction timing)" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_policy_check",
    description: "Dry-run policy evaluation without signing. Check if a transaction would be approved.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        unsigned_tx: { type: "string" }
      },
      required: ["wallet_address", "unsigned_tx"]
    }
  },
  {
    name: "wallet_rotate",
    description: "Rotate the agent wallet signing key. Disables old key and generates new one.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        reason: { type: "string" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_list",
    description: "List all managed wallets, optionally filtered by network.",
    inputSchema: {
      type: "object",
      properties: {
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] }
      }
    }
  },
  {
    name: "wallet_history",
    description: "Retrieve transaction history for audit and analysis.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        limit: { type: "number", minimum: 1, maximum: 100 },
        marker: { type: "string" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_fund",
    description: "Fund wallet from testnet/devnet faucet with automatic retry until account is queryable. Returns initial_balance_drops for test verification.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        network: { type: "string", enum: ["testnet", "devnet"] },
        wait_for_confirmation: { type: "boolean", description: "Wait for account to be queryable on validated ledger (default: true)" }
      },
      required: ["wallet_address", "network"]
    }
  },
  {
    name: "policy_set",
    description: "Update wallet policy (requires approval). Changes security constraints.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        policy: { type: "object" },
        reason: { type: "string" }
      },
      required: ["wallet_address", "policy", "reason"]
    }
  },
  {
    name: "tx_submit",
    description: "Submit signed transaction to XRPL network.",
    inputSchema: {
      type: "object",
      properties: {
        signed_tx: { type: "string" },
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] },
        wait_for_validation: { type: "boolean" }
      },
      required: ["signed_tx", "network"]
    }
  },
  {
    name: "tx_decode",
    description: "Decode transaction blob for inspection. Works with signed or unsigned transactions.",
    inputSchema: {
      type: "object",
      properties: {
        tx_blob: { type: "string" }
      },
      required: ["tx_blob"]
    }
  }
];
function formatError(error) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (typeof error === "object" && error !== null && "code" in error && "message" in error && "timestamp" in error) {
    return error;
  }
  if (error instanceof Error) {
    const isDevelopment = process.env["NODE_ENV"] !== "production";
    console.error("[Server] Internal error:", error.message);
    if (isDevelopment) {
      console.error(error.stack);
    }
    return {
      code: "INTERNAL_ERROR",
      message: error.message,
      // Only include stack trace in development to avoid information disclosure
      details: isDevelopment ? { stack: error.stack } : void 0,
      timestamp
    };
  }
  return {
    code: "INTERNAL_ERROR",
    message: "An unknown error occurred",
    // Don't expose raw error details in production
    details: process.env["NODE_ENV"] !== "production" ? { error: String(error) } : void 0,
    timestamp
  };
}
function createServer(context, config) {
  const server = new Server(
    {
      name: config?.name ?? "xrpl-agent-wallet-mcp",
      version: config?.version ?? "0.1.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      const toolDef = TOOLS.find((t) => t.name === name);
      if (!toolDef) {
        throw new Error(`Unknown tool: ${name}`);
      }
      const inputSchema = InputSchemas[name];
      if (!inputSchema) {
        throw new Error(`No schema found for tool: ${name}`);
      }
      const validatedInput = inputSchema.parse(args);
      let result;
      switch (name) {
        case "wallet_create":
          result = await handleWalletCreate(context, validatedInput);
          break;
        case "wallet_sign":
          result = await handleWalletSign(context, validatedInput);
          break;
        case "wallet_balance":
          result = await handleWalletBalance(context, validatedInput);
          break;
        case "wallet_policy_check":
          result = await handleWalletPolicyCheck(context, validatedInput);
          break;
        case "wallet_rotate":
          result = await handleWalletRotate(context, validatedInput);
          break;
        case "wallet_list":
          result = await handleWalletList(context, validatedInput);
          break;
        case "wallet_history":
          result = await handleWalletHistory(context, validatedInput);
          break;
        case "wallet_fund":
          result = await handleWalletFund(context, validatedInput);
          break;
        case "policy_set":
          result = await handlePolicySet(context, validatedInput);
          break;
        case "tx_submit":
          result = await handleTxSubmit(context, validatedInput);
          break;
        case "tx_decode":
          result = await handleTxDecode(context, validatedInput);
          break;
        default:
          throw new Error(`Handler not implemented for tool: ${name}`);
      }
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorResponse = formatError(error);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorResponse, null, 2)
          }
        ],
        isError: true
      };
    }
  });
  return server;
}
async function runServer(context, config) {
  const server = createServer(context, config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  await context.auditLogger.log({
    event: "server_started"
  });
  console.error("XRPL Agent Wallet MCP Server running on stdio");
}
/*! Bundled license information:

@noble/hashes/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/lib/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/weierstrass.js:
@noble/curves/_shortw_utils.js:
@noble/curves/secp256k1.js:
@noble/curves/abstract/edwards.js:
@noble/curves/abstract/montgomery.js:
@noble/curves/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/

export { AES_CONFIG2 as AES_CONFIG, ARGON2_CONFIG2 as ARGON2_CONFIG, AccountNotFoundError, AuditLogInputSchema, AuditLogger, AuthenticationError, BackupFormatError, ChainStateSchema, ConnectionError, DEFAULT_AUDIT_LOGGER_CONFIG, DEFAULT_CONNECTION_CONFIG, DEFAULT_PASSWORD_POLICY2 as DEFAULT_PASSWORD_POLICY, EXPLORER_URLS, FAUCET_CONFIG, GENESIS_CONSTANT, HMAC_ALGORITHM, HMAC_KEY_LENGTH, HashChain, HmacKeySchema, InvalidKeyError, KeyDecryptionError, KeyEncryptionError, KeystoreCapacityError, KeystoreError, KeystoreInitializationError, KeystoreReadError, KeystoreWriteError, LimitExceededError, LimitTracker, LocalKeystore, MaxReconnectAttemptsError, MultiSignError, MultiSignOrchestrator, NETWORK_ENDPOINTS, NetworkMismatchError, PolicyEngine, PolicyError, PolicyEvaluationError, PolicyIntegrityError, PolicyLoadError, PolicyValidationError, ProviderUnavailableError, RuleEvaluator, SecureBuffer, SigningError, SigningService, TransactionTimeoutError, VerificationOptionsSchema, WalletExistsError, WalletNotFoundError, WeakPasswordError, XRPLClientError, XRPLClientWrapper, checkBlocklist, computeStandaloneHash, createLimitTracker, createMemoryKeyProvider, createPolicyEngine, createServer, createTestPolicy, generateHmacKey, getAccountExplorerUrl, getBackupWebSocketUrls, getConnectionConfig, getDefaultAuditDir, getFaucetUrl, getLedgerExplorerUrl, getTransactionCategory, getTransactionExplorerUrl, getWebSocketUrl, isFaucetAvailable, isInAllowlist, isKeystoreError, isKeystoreErrorCode, isValidHmacKey, numericToTier, runServer, sanitizeForLogging, tierToNumeric };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map