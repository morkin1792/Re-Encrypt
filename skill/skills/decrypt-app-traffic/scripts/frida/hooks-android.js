/*
 * hooks-android.js — capture every key, IV, MAC key and plaintext the app feeds to Java crypto.
 *
 *   frida -U -f com.target.app -l hooks-android.js            # spawn (catches startup crypto)
 *   frida -U -n com.target.app -l hooks-android.js            # attach to a running app
 *   python3 ../frida-run.py com.target.app --key-file /tmp/aes.key   # + live key file for Re:Encrypt
 *
 * Why hook the *object* and not hunt for key bytes: an AndroidKeyStore or native-derived key may
 * never exist as a Java string, but `Cipher.init` still receives a usable SecretKey, and `doFinal`
 * still sees both sides of the transform. Reading those two calls tells you the algorithm, the key,
 * the IV and the plaintext at once.
 *
 * Each event is printed as one JSON line prefixed with [CRYPTO] and also sent via send() so
 * frida-run.py can maintain a live key file. Tune the CONFIG block below.
 */

const CONFIG = {
  maxBody: 4096,          // bytes of plaintext/ciphertext to report per call
  dedupeKeys: true,       // report each distinct key/IV once
  stacks: "keys",         // "none" | "keys" (stack for key material only) | "all"
  hookMac: true,          // Mac = the body signature / HMAC path
  hookDigest: false,      // MessageDigest: noisy, enable when hunting a signature input
  hookBase64: false,      // android.util.Base64: very noisy, occasionally reveals the wrapper
  hookRsa: true,          // RSA Cipher + public-key parsing (hybrid key exchange)
  hookNative: true,       // BoringSSL/OpenSSL EVP_* in libcrypto.so (Flutter, native stacks)
};

const seen = new Set();

function emit(event) {
  const line = JSON.stringify(event);
  console.log("[CRYPTO] " + line);
  try { send(event); } catch (e) { /* no host script attached */ }
}

function hex(bytes) {
  if (bytes === null) return null;
  const b = Java.array("byte", bytes);
  let out = "";
  for (let i = 0; i < b.length; i++) out += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return out;
}

function preview(bytes, limit) {
  if (bytes === null) return null;
  const b = Java.array("byte", bytes);
  const n = Math.min(b.length, limit || CONFIG.maxBody);
  let ascii = "", printable = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i] & 0xff;
    if (c >= 0x20 && c < 0x7f) { ascii += String.fromCharCode(c); printable++; }
    else ascii += ".";
  }
  const asText = printable / Math.max(n, 1) > 0.85;
  let h = "";
  for (let i = 0; i < n; i++) h += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return { length: b.length, text: asText ? ascii : null, hex: asText ? null : h };
}

function once(kind, value) {
  if (!CONFIG.dedupeKeys) return true;
  const k = kind + ":" + value;
  if (seen.has(k)) return false;
  seen.add(k);
  return true;
}

function stack(kind) {
  if (CONFIG.stacks === "none") return undefined;
  if (CONFIG.stacks === "keys" && kind !== "key") return undefined;
  const Log = Java.use("android.util.Log");
  const Exception = Java.use("java.lang.Exception");
  return Log.getStackTraceString(Exception.$new())
    .split("\n").filter(l => l.indexOf("at ") >= 0 && l.indexOf("javax.crypto") < 0)
    .slice(0, 8).map(l => l.trim());
}

Java.perform(function () {
  // ---------------------------------------------------------------- key material at construction
  const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (k, algo) {
    const h = hex(k);
    if (once("key", h)) {
      emit({ ev: "key", algorithm: algo, bytes: k.length, hex: h,
             utf8: preview(k, 64).text, stack: stack("key") });
    }
    return this.$init(k, algo);
  };
  SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation =
    function (k, off, len, algo) {
      const sub = Java.array("byte", k).slice(off, off + len);
      emit({ ev: "key", algorithm: algo, bytes: len, hex: hex(sub), stack: stack("key") });
      return this.$init(k, off, len, algo);
    };

  const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
  IvParameterSpec.$init.overload("[B").implementation = function (iv) {
    const h = hex(iv);
    if (once("iv", h)) emit({ ev: "iv", bytes: iv.length, hex: h });
    return this.$init(iv);
  };

  try {
    const GCMSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
    GCMSpec.$init.overload("int", "[B").implementation = function (tagLen, iv) {
      emit({ ev: "iv", kind: "gcm", tagBits: tagLen, bytes: iv.length, hex: hex(iv) });
      return this.$init(tagLen, iv);
    };
  } catch (e) { /* older API level */ }

  // ---------------------------------------------------------------- key derivation
  try {
    const PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
    PBEKeySpec.$init.overload("[C", "[B", "int", "int").implementation = function (pw, salt, it, len) {
      emit({ ev: "kdf", scheme: "PBKDF2", password: Java.use("java.lang.String").$new(pw).toString(),
             saltHex: hex(salt), iterations: it, keyBits: len, stack: stack("key") });
      return this.$init(pw, salt, it, len);
    };
  } catch (e) { /* not present */ }

  try {
    const SKF = Java.use("javax.crypto.SecretKeyFactory");
    SKF.generateSecret.implementation = function (spec) {
      const key = this.generateSecret(spec);
      try {
        const enc = key.getEncoded();
        if (enc !== null) emit({ ev: "key", source: "SecretKeyFactory", algorithm: key.getAlgorithm(),
                                 bytes: enc.length, hex: hex(enc) });
      } catch (e) { /* non-extractable */ }
      return key;
    };
  } catch (e) { /* not present */ }

  // ---------------------------------------------------------------- Cipher
  const Cipher = Java.use("javax.crypto.Cipher");
  const cipherState = {};   // handle -> {transform, mode, keyHex, ivHex}

  Cipher.getInstance.overload("java.lang.String").implementation = function (t) {
    const c = this.getInstance(t);
    cipherState[c.hashCode()] = { transform: t };
    return c;
  };
  Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (t, p) {
    const c = this.getInstance(t, p);
    cipherState[c.hashCode()] = { transform: t, provider: p };
    return c;
  };

  function recordInit(self, opmode, key, params) {
    const st = cipherState[self.hashCode()] || {};
    st.transform = st.transform || String(self.getAlgorithm());
    st.opmode = { 1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP" }[opmode] || opmode;
    try {
      const enc = key.getEncoded();
      st.keyHex = enc === null ? "<non-extractable (keystore/HW)>" : hex(enc);
      st.keyBytes = enc === null ? null : enc.length;
    } catch (e) { st.keyHex = "<getEncoded threw: " + e + ">"; }
    st.keyClass = key.$className;
    try {
      const iv = self.getIV();
      st.ivHex = iv === null ? null : hex(iv);
    } catch (e) { /* no iv yet */ }
    cipherState[self.hashCode()] = st;
    emit({ ev: "cipher.init", transform: st.transform, opmode: st.opmode, keyClass: st.keyClass,
           keyBytes: st.keyBytes, keyHex: st.keyHex, ivHex: st.ivHex, stack: stack("key") });
  }

  Cipher.init.overload("int", "java.security.Key").implementation = function (m, k) {
    recordInit(this, m, k, null); return this.init(m, k);
  };
  Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
    .implementation = function (m, k, p) { recordInit(this, m, k, p); return this.init(m, k, p); };
  Cipher.init.overload("int", "java.security.Key", "java.security.SecureRandom")
    .implementation = function (m, k, r) { recordInit(this, m, k, null); return this.init(m, k, r); };
  try {
    Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec",
                         "java.security.SecureRandom")
      .implementation = function (m, k, p, r) { recordInit(this, m, k, p); return this.init(m, k, p, r); };
    Cipher.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters")
      .implementation = function (m, k, p) { recordInit(this, m, k, p); return this.init(m, k, p); };
  } catch (e) { /* overload set varies by API level */ }

  function reportDoFinal(self, input, output) {
    const st = cipherState[self.hashCode()] || {};
    const encrypting = st.opmode === "ENCRYPT" || st.opmode === "WRAP";
    let iv = st.ivHex;
    try { const raw = self.getIV(); if (raw !== null) iv = hex(raw); } catch (e) { /* none */ }
    emit({
      ev: "cipher.doFinal",
      transform: st.transform || String(self.getAlgorithm()),
      opmode: st.opmode, keyHex: st.keyHex, ivHex: iv,
      plaintext: preview(encrypting ? input : output),
      ciphertext: preview(encrypting ? output : input),
      stack: stack("data"),
    });
  }

  Cipher.doFinal.overload("[B").implementation = function (input) {
    const out = this.doFinal(input);
    reportDoFinal(this, input, out);
    return out;
  };
  Cipher.doFinal.overload("[B", "int", "int").implementation = function (input, off, len) {
    const out = this.doFinal(input, off, len);
    reportDoFinal(this, Java.array("byte", input).slice(off, off + len), out);
    return out;
  };
  Cipher.doFinal.overload().implementation = function () {
    const out = this.doFinal();
    reportDoFinal(this, null, out);
    return out;
  };

  // ---------------------------------------------------------------- Mac (body signature)
  if (CONFIG.hookMac) {
    const Mac = Java.use("javax.crypto.Mac");
    Mac.init.overload("java.security.Key").implementation = function (k) {
      let kh = null;
      try { const e = k.getEncoded(); kh = e === null ? "<non-extractable>" : hex(e); } catch (e) { }
      emit({ ev: "mac.init", algorithm: String(this.getAlgorithm()), keyHex: kh, stack: stack("key") });
      return this.init(k);
    };
    Mac.doFinal.overload("[B").implementation = function (input) {
      const out = this.doFinal(input);
      emit({ ev: "mac.doFinal", algorithm: String(this.getAlgorithm()),
             signedInput: preview(input), macHex: hex(out) });
      return out;
    };
    Mac.doFinal.overload().implementation = function () {
      const out = this.doFinal();
      emit({ ev: "mac.doFinal", algorithm: String(this.getAlgorithm()), macHex: hex(out) });
      return out;
    };
    Mac.update.overload("[B").implementation = function (input) {
      emit({ ev: "mac.update", algorithm: String(this.getAlgorithm()), chunk: preview(input) });
      return this.update(input);
    };
  }

  // ---------------------------------------------------------------- digests
  if (CONFIG.hookDigest) {
    const MD = Java.use("java.security.MessageDigest");
    MD.digest.overload("[B").implementation = function (input) {
      const out = this.digest(input);
      emit({ ev: "digest", algorithm: String(this.getAlgorithm()), input: preview(input), hex: hex(out) });
      return out;
    };
  }

  // ---------------------------------------------------------------- RSA / key exchange
  if (CONFIG.hookRsa) {
    try {
      const X509 = Java.use("java.security.spec.X509EncodedKeySpec");
      X509.$init.overload("[B").implementation = function (der) {
        emit({ ev: "publicKey", format: "X509/DER", bytes: der.length, base64: b64(der),
               stack: stack("key") });
        return this.$init(der);
      };
    } catch (e) { /* not present */ }
    try {
      const PKCS8 = Java.use("java.security.spec.PKCS8EncodedKeySpec");
      PKCS8.$init.overload("[B").implementation = function (der) {
        emit({ ev: "privateKey", format: "PKCS8/DER", bytes: der.length, base64: b64(der),
               stack: stack("key") });
        return this.$init(der);
      };
    } catch (e) { /* not present */ }
    try {
      const KF = Java.use("java.security.KeyFactory");
      KF.generatePublic.implementation = function (spec) {
        const k = this.generatePublic(spec);
        emit({ ev: "publicKey.parsed", algorithm: String(k.getAlgorithm()),
               base64: b64(k.getEncoded()) });
        return k;
      };
    } catch (e) { /* not present */ }
  }

  function b64(bytes) {
    const B64 = Java.use("android.util.Base64");
    return B64.encodeToString(bytes, 2);   // NO_WRAP
  }

  if (CONFIG.hookBase64) {
    const B64 = Java.use("android.util.Base64");
    B64.encodeToString.overload("[B", "int").implementation = function (data, flags) {
      const out = this.encodeToString(data, flags);
      emit({ ev: "base64.encode", input: preview(data), output: out.substring(0, 200) });
      return out;
    };
    B64.decode.overload("java.lang.String", "int").implementation = function (s, flags) {
      const out = this.decode(s, flags);
      emit({ ev: "base64.decode", input: s.substring(0, 200), output: preview(out) });
      return out;
    };
  }

  console.log("[CRYPTO] Java hooks installed (Cipher, SecretKeySpec, IvParameterSpec, Mac" +
              (CONFIG.hookRsa ? ", RSA key specs" : "") + ")");
});

// -------------------------------------------------------------------- native (BoringSSL / OpenSSL)
// Flutter, Cronet and many native SDKs never touch javax.crypto. These two exports give you the key
// and the mode without any Java involvement.
if (CONFIG.hookNative) {
  ["libcrypto.so", "libssl.so", "libnative-lib.so"].forEach(function (lib) {
    ["EVP_EncryptInit_ex", "EVP_DecryptInit_ex"].forEach(function (sym) {
      const addr = Module.findExportByName(lib, sym);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          // (ctx, cipher, engine, key, iv)
          const cipherPtr = args[1];
          let name = "?";
          try {
            const nameFn = Module.findExportByName(lib, "EVP_CIPHER_name") ||
                           Module.findExportByName(lib, "EVP_CIPHER_get0_name");
            if (nameFn && !cipherPtr.isNull()) {
              name = new NativeFunction(nameFn, "pointer", ["pointer"])(cipherPtr).readCString();
            }
          } catch (e) { /* name lookup unavailable */ }
          const keyLen = /aes-256/.test(name) ? 32 : /aes-192/.test(name) ? 24 : 16;
          const ivLen = /gcm/.test(name) ? 12 : 16;
          const ev = { ev: "native.evp", symbol: sym, lib: lib, cipher: name,
                       keyHex: args[3].isNull() ? null : hexPtr(args[3], keyLen),
                       ivHex: args[4].isNull() ? null : hexPtr(args[4], ivLen) };
          console.log("[CRYPTO] " + JSON.stringify(ev));
          try { send(ev); } catch (e) { }
        },
      });
      console.log("[CRYPTO] native hook on " + lib + "!" + sym);
    });
  });
}

function hexPtr(ptr, len) {
  const bytes = new Uint8Array(ptr.readByteArray(len));
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += ("0" + bytes[i].toString(16)).slice(-2);
  return out;
}
