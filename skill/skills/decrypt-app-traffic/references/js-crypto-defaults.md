# JS crypto libraries: what their defaults actually do

A large share of "the app encrypts its body" cases are a JS library called with a hardcoded string, in
a React Native / Cordova / WebView client. The library's *defaults* are the scheme — and they are not
what the call site looks like. These are the ones that cost people hours.

## CryptoJS — a **string** key is a passphrase, not a key

```js
CryptoJS.AES.encrypt(plaintext, "7x!A%D*G-KaPdSgV")            // (a) passphrase form
CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Utf8.parse(k), {iv: iv})   // (b) raw-key form
```

**(a) String key → OpenSSL envelope.** CryptoJS treats the string as a *password*: it generates a
random 8-byte salt, derives key **and** IV with `EVP_BytesToKey` (MD5, 1 iteration), encrypts
AES-**256**-CBC/PKCS7, and emits `"Salted__" + salt + ciphertext` in base64. On the wire that always
starts **`U2FsdGVkX1`** — the single most recognisable string in this whole domain.

Consequences that trip people up:
- The key is **AES-256 regardless of how short the passphrase is.** A 16-character literal does *not*
  mean AES-128, and feeding those 16 bytes as a raw key yields garbage.
- There is no IV on the wire; it comes out of the KDF with the key.
- The salt is fresh per message, so two encryptions of the same plaintext differ — that is the library,
  not the app being careful.

Handle it with either:
```bash
crypto-cli.py dec --structure openssl --mode CBC --kdf evp-md5 --key 'utf8:<passphrase>' --in-file {FILE}
node "$SKILL"/scripts/oracle/js-crypto-oracle.js dec --lib cryptojs --key '<passphrase>' --file {FILE}
```
(Verified byte-compatible in both directions: `crypto-cli.py` output decrypts in CryptoJS and vice
versa. In Re:Encrypt, that is engine **AES** with `ciphertextStructure=openssl`, `keyDerivation=evp_md5`,
key format **UTF-8**.)

**(b) WordArray key → raw key bytes, and an IV is mandatory.** Once the key is `enc.Utf8.parse(...)`
/ `enc.Hex.parse(...)`, no KDF and no salt happen: key length = the literal's length (16 chars →
AES-128), output is bare base64 ciphertext, and CryptoJS **throws** for CBC/CTR/CFB/OFB unless the
call passes `{iv: …}` — there is no zero-IV default. So when you see the raw-key form, *the IV is in
the code next to it* (a hardcoded literal, a slice of the key, a constant) or the app prepends it to
the ciphertext itself. ECB is the exception: no IV, and then the same key alone decrypts everything.

If a solve run reports **"the output is missing its beginning"** on a CBC hit, you are in exactly this
case: right key, IV elsewhere.

Other CryptoJS defaults worth knowing: `mode` defaults to CBC, `padding` to Pkcs7, and
`CryptoJS.enc.Utf8.stringify` of a wrong-key result is an empty string — which is why the library
"fails silently" and the app usually swallows it.

## The others, in one line each

| Library | Tell in the bundle | Default scheme / envelope |
|---|---|---|
| **node-forge** | `forge.cipher.createCipher('AES-CBC', key)` | raw key bytes; you must supply the IV; output is a raw byte buffer the app encodes itself. `forge.pki.rsa.generateKeyPair` = a client keypair → key-exchange shape |
| **sjcl** | `sjcl.encrypt(pass, data)` | its own JSON envelope `{"iv","salt","ct","ks","ts","mode":"ccm","adata","cipher"}` — **AES-CCM**, PBKDF2(1000+) from a password. Use the oracle (`--lib sjcl`); reimplementing CCM by hand is not worth it |
| **JSEncrypt** | `new JSEncrypt(); setPublicKey(...)` | RSA **PKCS#1 v1.5**, base64, one block — length equals the modulus size. Only used for small payloads or to wrap a key |
| **WebCrypto** | `crypto.subtle.encrypt({name:'AES-GCM', iv}, …)` | exactly what the call says; IV/tag handling is the app's own — read the surrounding code, there are no hidden defaults |
| **tweetnacl / libsodium.js** | `nacl.secretbox(msg, nonce, key)` | XSalsa20-Poly1305, 24-byte nonce, 16-byte tag prefix — not AES at all; use the library (or PyNaCl) rather than `crypto-cli.py` |
| **Java `SecretKeySpec(k.getBytes(), "AES")`** | in a Java/Kotlin app | raw bytes of the literal, so a 16-char literal *is* AES-128 — the opposite of CryptoJS's string form. Don't carry the assumption across languages |

## When you don't know which literal is the key

The passphrase can be any length, so shape-based ranking won't always surface it. Harvest every quoted
literal from the file that does the crypto and let the solver decide:

```bash
rg -o "['\"]([\x21-\x7e]{6,40})['\"]" -r '$1' static/www static/jadx | sort -u > keys.txt
crypto-cli.py solve --key-candidates keys.txt --in-file samples/ct1.txt --max-attempts 200000
```

That is a few hundred candidates — ~17 s with `pycryptodome` installed, ~1.5 min on the openssl-CLI
fallback (one process per attempt), so install the library before a wide sweep.

## Reuse the app's own library as the oracle

When the envelope is bespoke (sjcl, a wrapper of a wrapper, a custom `format` object) don't reverse
it — call it. `$SKILL/scripts/oracle/js-crypto-oracle.js` is that wrapper for CryptoJS and sjcl, and it is
written to the proxy-command contract (reads `{FILE}`, writes only the result to stdout), so it drops
straight into Re:Encrypt's Decrypt/Encrypt Command fields:

```bash
npm i crypto-js sjcl        # anywhere; pass --modules <dir> if it isn't the cwd
node "$SKILL"/scripts/oracle/js-crypto-oracle.js dec --lib auto --key '<literal>' --file {FILE}
```

Same idea for any language: a ten-line script that imports the app's library and exposes
dec/enc over argv beats a careful reimplementation, and it can't disagree with the client.

For a WebView app you can go one step further and use the app's *live* code as the oracle: with
`chrome://inspect` attached, call its own encrypt/decrypt functions from the console
(`sfCrypto.encrypt(JSON.stringify(payload))`), which settles every question about defaults at once.
