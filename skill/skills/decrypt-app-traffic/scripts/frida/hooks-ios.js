/*
 * hooks-ios.js — capture keys, IVs, HMACs and plaintext from CommonCrypto / Security.framework.
 *
 *   frida -U -f com.target.app -l hooks-ios.js
 *   frida -U -n TargetApp -l hooks-ios.js
 *   python3 ../frida-run.py com.target.app --platform ios --key-file /tmp/aes.key
 *
 * On iOS almost all app-level symmetric crypto lands in one of two places: CCCrypt (one-shot) or
 * CCCryptorCreate[WithMode] + CCCryptorUpdate (streaming). Hooking those four gives you the
 * algorithm, mode, key and IV. RSA/key wrapping goes through SecKeyCreateEncryptedData /
 * SecKeyCreateDecryptedData. Third-party stacks (CryptoSwift, RNCryptor, OpenSSL builds) are covered
 * by the extra scans at the bottom.
 */

const CONFIG = {
  maxBody: 4096,
  dedupeKeys: true,
  backtrace: "keys",     // "none" | "keys" | "all"
};

const seen = new Set();

const CC_ALG = { 0: "AES", 1: "DES", 2: "3DES", 3: "CAST", 4: "RC4", 5: "RC2", 6: "Blowfish" };
const CC_OP = { 0: "ENCRYPT", 1: "DECRYPT" };
const CC_MODE = { 1: "ECB", 2: "CBC", 3: "CFB", 4: "CTR", 5: "F8", 6: "LRW", 7: "OFB", 8: "XTS",
                  9: "RC4", 10: "CFB8" };
const CC_HMAC_ALG = { 0: "SHA1", 1: "MD5", 2: "SHA256", 3: "SHA384", 4: "SHA512", 5: "SHA224" };

function emit(event) {
  console.log("[CRYPTO] " + JSON.stringify(event));
  try { send(event); } catch (e) { /* no host script attached */ }
}

function hexPtr(ptr, len) {
  if (ptr === null || ptr.isNull() || len <= 0) return null;
  const bytes = new Uint8Array(ptr.readByteArray(Math.min(len, 4096)));
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += ("0" + bytes[i].toString(16)).slice(-2);
  return out;
}

function preview(ptr, len) {
  if (ptr === null || ptr.isNull() || len <= 0) return null;
  const n = Math.min(len, CONFIG.maxBody);
  const bytes = new Uint8Array(ptr.readByteArray(n));
  let ascii = "", printable = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if (c >= 0x20 && c < 0x7f) { ascii += String.fromCharCode(c); printable++; } else ascii += ".";
  }
  const asText = printable / n > 0.85;
  return { length: len, text: asText ? ascii : null, hex: asText ? null : hexPtr(ptr, n) };
}

function once(kind, value) {
  if (!CONFIG.dedupeKeys || value === null) return true;
  const k = kind + ":" + value;
  if (seen.has(k)) return false;
  seen.add(k);
  return true;
}

function bt(ctx, kind) {
  if (CONFIG.backtrace === "none") return undefined;
  if (CONFIG.backtrace === "keys" && kind !== "key") return undefined;
  return Thread.backtrace(ctx, Backtracer.ACCURATE)
    .slice(0, 8).map(DebugSymbol.fromAddress).map(String);
}

// ---------------------------------------------------------------- CCCrypt (one-shot)
const CCCrypt = Module.findExportByName(null, "CCCrypt");
if (CCCrypt) {
  Interceptor.attach(CCCrypt, {
    onEnter: function (args) {
      // CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvail, dataOutMoved)
      this.op = args[0].toInt32();
      this.alg = args[1].toInt32();
      this.options = args[2].toInt32();
      this.keyLen = args[4].toInt32();
      this.keyHex = hexPtr(args[3], this.keyLen);
      this.ivHex = hexPtr(args[5], 16);
      this.inLen = args[7].toInt32();
      this.inPtr = args[6];
      this.outPtr = args[8];
      this.movedPtr = args[10];
    },
    onLeave: function (retval) {
      const outLen = this.movedPtr.isNull() ? 0 : this.movedPtr.readU32();
      const encrypting = this.op === 0;
      emit({
        ev: "CCCrypt",
        algorithm: CC_ALG[this.alg] || this.alg,
        operation: CC_OP[this.op] || this.op,
        mode: (this.options & 2) ? "ECB" : "CBC",           // kCCOptionECBMode = 2
        padding: (this.options & 1) ? "PKCS7" : "none",     // kCCOptionPKCS7Padding = 1
        keyBytes: this.keyLen, keyHex: this.keyHex, ivHex: this.ivHex,
        plaintext: encrypting ? preview(this.inPtr, this.inLen) : preview(this.outPtr, outLen),
        ciphertext: encrypting ? preview(this.outPtr, outLen) : preview(this.inPtr, this.inLen),
        status: retval.toInt32(),
        backtrace: bt(this.context, "key"),
      });
    },
  });
  console.log("[CRYPTO] hooked CCCrypt");
}

// ---------------------------------------------------------------- CCCryptorCreate[WithMode]
const cryptorKeys = {};   // cryptorRef -> key/iv/mode

const CCCryptorCreate = Module.findExportByName(null, "CCCryptorCreate");
if (CCCryptorCreate) {
  Interceptor.attach(CCCryptorCreate, {
    onEnter: function (args) {
      this.op = args[0].toInt32(); this.alg = args[1].toInt32(); this.options = args[2].toInt32();
      this.keyLen = args[4].toInt32();
      this.keyHex = hexPtr(args[3], this.keyLen);
      this.ivHex = hexPtr(args[5], 16);
      this.refOut = args[6];
    },
    onLeave: function () {
      const ref = this.refOut.isNull() ? null : this.refOut.readPointer();
      const info = { algorithm: CC_ALG[this.alg] || this.alg, operation: CC_OP[this.op] || this.op,
                     mode: (this.options & 2) ? "ECB" : "CBC", keyBytes: this.keyLen,
                     keyHex: this.keyHex, ivHex: this.ivHex };
      if (ref) cryptorKeys[ref.toString()] = info;
      if (once("key", this.keyHex + "|" + this.ivHex)) {
        emit(Object.assign({ ev: "CCCryptorCreate" }, info, { backtrace: bt(this.context, "key") }));
      }
    },
  });
  console.log("[CRYPTO] hooked CCCryptorCreate");
}

const CCCryptorCreateWithMode = Module.findExportByName(null, "CCCryptorCreateWithMode");
if (CCCryptorCreateWithMode) {
  Interceptor.attach(CCCryptorCreateWithMode, {
    onEnter: function (args) {
      // (op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, cryptorRef)
      this.op = args[0].toInt32(); this.mode = args[1].toInt32(); this.alg = args[2].toInt32();
      this.padding = args[3].toInt32();
      this.ivHex = hexPtr(args[4], 16);
      this.keyLen = args[6].toInt32();
      this.keyHex = hexPtr(args[5], this.keyLen);
      this.refOut = args[11];
    },
    onLeave: function () {
      const ref = this.refOut.isNull() ? null : this.refOut.readPointer();
      const info = { algorithm: CC_ALG[this.alg] || this.alg, operation: CC_OP[this.op] || this.op,
                     mode: CC_MODE[this.mode] || this.mode,
                     padding: this.padding === 1 ? "PKCS7" : "none",
                     keyBytes: this.keyLen, keyHex: this.keyHex, ivHex: this.ivHex };
      if (ref) cryptorKeys[ref.toString()] = info;
      if (once("key", this.keyHex + "|" + this.ivHex + "|" + this.mode)) {
        emit(Object.assign({ ev: "CCCryptorCreateWithMode" }, info,
                           { backtrace: bt(this.context, "key") }));
      }
    },
  });
  console.log("[CRYPTO] hooked CCCryptorCreateWithMode");
}

const CCCryptorUpdate = Module.findExportByName(null, "CCCryptorUpdate");
if (CCCryptorUpdate) {
  Interceptor.attach(CCCryptorUpdate, {
    onEnter: function (args) {
      this.ref = args[0].toString();
      this.inPtr = args[1]; this.inLen = args[2].toInt32();
      this.outPtr = args[3]; this.movedPtr = args[5];
    },
    onLeave: function () {
      const info = cryptorKeys[this.ref] || {};
      const outLen = this.movedPtr.isNull() ? 0 : this.movedPtr.readU32();
      const encrypting = info.operation === "ENCRYPT";
      emit({ ev: "CCCryptorUpdate", algorithm: info.algorithm, mode: info.mode,
             operation: info.operation, keyHex: info.keyHex, ivHex: info.ivHex,
             plaintext: encrypting ? preview(this.inPtr, this.inLen) : preview(this.outPtr, outLen),
             ciphertext: encrypting ? preview(this.outPtr, outLen) : preview(this.inPtr, this.inLen) });
    },
  });
}

// ---------------------------------------------------------------- CCHmac (body signature)
const CCHmac = Module.findExportByName(null, "CCHmac");
if (CCHmac) {
  Interceptor.attach(CCHmac, {
    onEnter: function (args) {
      // (algorithm, key, keyLength, data, dataLength, macOut)
      this.alg = args[0].toInt32();
      this.keyLen = args[2].toInt32();
      this.keyHex = hexPtr(args[1], this.keyLen);
      this.data = preview(args[3], args[4].toInt32());
      this.macOut = args[5];
      this.macLen = { 0: 20, 1: 16, 2: 32, 3: 48, 4: 64, 5: 28 }[this.alg] || 32;
    },
    onLeave: function () {
      emit({ ev: "CCHmac", algorithm: "HMAC-" + (CC_HMAC_ALG[this.alg] || this.alg),
             keyHex: this.keyHex, signedInput: this.data, macHex: hexPtr(this.macOut, this.macLen),
             backtrace: bt(this.context, "key") });
    },
  });
  console.log("[CRYPTO] hooked CCHmac");
}

// ---------------------------------------------------------------- CCKeyDerivationPBKDF
const PBKDF = Module.findExportByName(null, "CCKeyDerivationPBKDF");
if (PBKDF) {
  Interceptor.attach(PBKDF, {
    onEnter: function (args) {
      // (algorithm, password, passwordLen, salt, saltLen, prf, rounds, derivedKey, derivedKeyLen)
      this.pw = args[1].readUtf8String(args[2].toInt32());
      this.salt = hexPtr(args[3], args[4].toInt32());
      this.rounds = args[6].toInt32();
      this.dk = args[7]; this.dkLen = args[8].toInt32();
    },
    onLeave: function () {
      emit({ ev: "PBKDF2", password: this.pw, saltHex: this.salt, rounds: this.rounds,
             derivedKeyHex: hexPtr(this.dk, this.dkLen) });
    },
  });
}

// ---------------------------------------------------------------- Security.framework (RSA)
["SecKeyCreateEncryptedData", "SecKeyCreateDecryptedData"].forEach(function (sym) {
  const addr = Module.findExportByName(null, sym);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.sym = sym; this.algo = args[1]; },
    onLeave: function () {
      let algoName = null;
      if (ObjC.available) {
        try { algoName = new ObjC.Object(this.algo).toString(); } catch (e) { }
      }
      emit({ ev: this.sym, algorithm: algoName, backtrace: bt(this.context, "key") });
    },
  });
  console.log("[CRYPTO] hooked " + sym);
});

// ---------------------------------------------------------------- third-party stacks
if (ObjC.available) {
  ["RNCryptor", "AESCrypt", "CryptoSwift", "NSData+AES", "JOSESwift", "SwiftyRSA"].forEach(function (needle) {
    const hits = Object.keys(ObjC.classes).filter(c => c.indexOf(needle) >= 0);
    if (hits.length) console.log("[CRYPTO] third-party crypto classes: " + hits.slice(0, 8).join(", "));
  });
  const appClasses = Object.keys(ObjC.classes).filter(
    c => /Crypt|Cipher|AES|RSA|Sign|Secure|JWE|Token/i.test(c) && !/^(NS|_|CF|UI)/.test(c));
  if (appClasses.length) {
    console.log("[CRYPTO] app classes worth tracing: " + appClasses.slice(0, 20).join(", "));
    console.log("[CRYPTO] trace one with: frida-trace -U -n <app> -m '-[ClassName *]'");
  }
}

// OpenSSL/BoringSSL compiled into the app
["EVP_EncryptInit_ex", "EVP_DecryptInit_ex"].forEach(function (sym) {
  const addr = Module.findExportByName(null, sym);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      emit({ ev: "native.evp", symbol: sym, keyHex: hexPtr(args[3], 32), ivHex: hexPtr(args[4], 16),
             note: "key length assumed 32 — cross-check against the cipher in use" });
    },
  });
  console.log("[CRYPTO] hooked " + sym + " (in-app OpenSSL)");
});
