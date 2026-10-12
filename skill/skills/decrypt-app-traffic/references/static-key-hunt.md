# Finding the key in the artifact

Cheapest path to a working setup: the key is in the app. Start here before any device work, and stop
the moment a captured sample decrypts.

**Check for prior work on this app first.** These schemes are remarkably stable — a hardcoded keypair
can survive years of releases and the handshake shape rarely changes. An old engagement folder, a
protocol note or a key log can replace the entire hunt; diff it against the current bundle and you are
done in minutes.

## Work from the triage report, not the whole app

`crypto-triage.py` already lists the transform strings, the crypto classes, the PEM blocks and the
ranked key candidates. Test the candidates *first* — a 30-second `crypto-cli.py dec` beats an hour of
reading:

```bash
for k in $(cut -d'`' -f2 <work>/triage/*.triage.md | grep -E '^[0-9a-f]{32,64}$'); do
  echo "== $k"; python3 "$SKILL"/scripts/crypto-cli.py dec --mode CBC --structure iv_ct --key hex:$k \
      --in-file <work>/samples/ct1.txt 2>/dev/null | head -c 120; echo
done
```

Try each candidate as **hex**, **base64** and **UTF-8** — the same 32 characters mean different bytes
in each, and apps are inconsistent.

## Then read the encrypt path

Open the classes the triage named (`jadx -d <out> app.apk`, or `jadx-gui` for navigation) and read
the function that builds the request body. You are looking for six things, in this order:

1. the transform string (`Cipher.getInstance("…")`),
2. where the key bytes come from (literal · `getString(R.string.…)` · assets · `BuildConfig` ·
   `System.loadLibrary` + a native getter · `KeyStore` · a server response),
3. where the IV comes from (random and prepended, or fixed),
4. any KDF (`PBEKeySpec`, `SecretKeyFactory`, MD5/SHA of a string, `EVP_BytesToKey`),
5. how the ciphertext is packed (concatenations, `Base64.encodeToString`, string formats),
6. whether a MAC/signature is computed over the result (see `integrity-and-signatures.md`).

Reproduce steps 1–5 with `crypto-cli.py`; if you can't, you've misread one of them — usually the key
encoding or an extra wrapping layer.

## Where keys hide, per stack

- **Java/Kotlin** — string literals in the DEX (already extracted by triage), `res/values/strings.xml`,
  `assets/`, `BuildConfig`, or split across several literals concatenated at runtime (grep for
  `StringBuilder` around the crypto class). Obfuscated apps keep the *string* but rename the class.
- **Native (`lib/*/*.so`)** — `strings` finds many keys; otherwise hook `EVP_EncryptInit_ex` (see
  `runtime-key-capture.md`) instead of reversing. Ghidra/radare2 only when you must read the KDF.
- **React Native** — `assets/index.android.bundle`. Plain JS: `js-beautify` it and read `CryptoJS`
  usage directly (mode, key, IV are all right there). Hermes bytecode (starts `\xC6\x1F\xBC\x03`):
  `hermes-dec` / `hbctool`, or hook at the native layer.
- **Flutter** — code is in `libapp.so`; use `reFlutter` or `blutter` for symbols, but hooking
  BoringSSL is usually faster than reversing Dart.
- **Cordova/Capacitor** — `assets/www/**/*.js`, plain source. Same for any WebView-driven flow: the
  page's JS is the spec (`crypto.subtle`, `CryptoJS`, `JSEncrypt`, `forge`).
- **iOS** — `Payload/*.app/`: the Mach-O (`strings`, `rabin2 -z`), `Info.plist`, embedded
  `.plist`/`.json` resources, and `Frameworks/`. `class-dump`/Ghidra for the encrypt method.
- **Unity/IL2CPP** — `global-metadata.dat` holds the string literals; `Il2CppDumper` then read.
- **Xamarin/MAUI** — `assemblies/*.dll`, decompile with `ilspycmd`.

## Derived keys: reproduce the KDF exactly

If a KDF is present, the shipped secret is a password. You need **every** input, and one wrong
parameter yields pure garbage:

- `PBKDF2WithHmacSHA256(password, salt, iterations, keyBits)` — salt is often a literal or the app id;
  iterations are often 1000/10000/65536.
- `EVP_BytesToKey` (OpenSSL `enc`) — MD5 by default, SHA-256 on newer builds; salt comes from the
  message. `crypto-cli.py --structure openssl --kdf evp-md5|evp-sha256|pbkdf2` covers both.
- Home-made: `SHA-256(password)`, `MD5(password)` twice, `key = first16(sha1(x))`, key XOR constant,
  reversed strings. Read it, don't guess it; then reimplement in a tiny wrapper script and pass it to
  Re:Encrypt as a custom command (or as a key `command` source).

## Look for a hardcoded key*pair*, not just a symmetric key

If the traffic uses a key exchange, the cheapest possible outcome is that the app's own keypair is a
literal instead of being generated per session. Then you decrypt the exchange yourself — passively,
with no interception, and on captures taken before you ever looked at the app.

What to grep for, in the artifact and in any JS bundle:

- `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----` (PKCS#8), `-----BEGIN EC PRIVATE KEY-----`
- base64 blobs assigned next to a public key (`priv = atob("MIIC…")`, `setPrivateKey(…)`) — a pair
  that ships together is the giveaway
- `.p12` / `.pfx` / `.jks` / `.bks` files in `assets/` or `res/raw/` (often with the password in the
  code nearby); `openssl pkcs12 -in x.p12 -nodes` to read one
- a `.der` key: no PEM header to grep, so look for files of ~1200 bytes in `assets/` and try
  `openssl rsa -inform DER -in f -noout -text`

`crypto-triage.py` writes every PEM block it finds to `<artifact>.pem.N`, so feed those straight into
`crypto-cli.py dec --engine rsa --priv file:<that file>` against the wrapped-key blob from the
handshake. If it decrypts, you have skipped rungs 2–4 entirely.

## Hybrid / WebView apps: read the JS, it's the spec

If the app serves its UI from `assets/www` (Cordova/Capacitor/Angular in a WebView), the entire crypto
implementation is readable JavaScript. `js-beautify` the bundle and you get mode, key handling, IV
handling, the wrappers, the handshake and the renewal logic — everything the rest of this skill has to
infer elsewhere. It is also the easiest thing to *patch* (`patch-the-client.md`). Always look here
first for a hybrid app.

## When to stop hunting statically

Stop when the key is not in the artifact at all:

- it arrives from the server, or is agreed in a handshake → `key-exchange-mitm.md` (take it at the
  proxy; that's the primary route, no device tooling);
- it is generated on the client, or lives in `AndroidKeyStore`/Secure Enclave, or is derived in native
  code from device data → `patch-the-client.md` (replace the keypair, or add one log line);
- only as a genuine last resort, hook the process → `runtime-key-capture.md`.

Heavy obfuscation is *not* a reason to jump to hooking: string literals usually survive it (the triage
report reads them straight out of the DEX), and a WebView bundle is not obfuscated at all.
