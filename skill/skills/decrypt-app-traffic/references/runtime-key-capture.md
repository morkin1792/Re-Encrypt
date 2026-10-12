# Runtime capture — the last resort

Hooking the live process is the **last** option, not the first. It is noisy, it needs `frida-server` (or
a gadget) on the device, apps in this space actively detect it, and it stops working the moment the app
is restarted without the agent. Everything it tells you can usually be obtained more cheaply:

| Instead of hooking | Do this | Reference |
|---|---|---|
| a key shipped in the app | read it out of the artifact | `static-key-hunt.md` |
| a negotiated / per-session key | **read the handshake**: substitute your public key in the exchange, or run the handshake yourself | `key-exchange-mitm.md` |
| "the key only exists at runtime" | it is usually still *negotiated over HTTP* — the negotiation is already in your proxy | `key-exchange-mitm.md` |
| a key generated on the client | replace the client's keypair with yours, permanently | `patch-the-client.md` |
| "I just need to see the value once" | patch in a log line, or read it in `chrome://inspect` for a hybrid app | `patch-the-client.md` |
| a keystore/native-derived key | patch the call site to log it | `patch-the-client.md` |

Reach for instrumentation when those genuinely don't apply: the app can't be repacked (signature
enforcement), the key never leaves native code, there is no key exchange to intercept, and you only need
a value or two to move on.

## If you do hook

```bash
python3 "$SKILL"/scripts/frida-run.py <package> --key-file <work>/keys/aes.key \
    --key-log <work>/keys/key --session <sid> --log <work>/events.jsonl      # --spawn for startup crypto
```

`--key-file` is rewritten atomically on every new key (Re:Encrypt key source **File** + *reload on every
operation*, or `crypto-cli.py --key file:hex:…`). `--key-log` appends `<ts>: <key> <session>` lines — the
same format the proxy-side capture writes, so one resolver reads both.

Without the frida python bindings: `frida -U -f <package> -l scripts/frida/hooks-android.js`
(`-n` to attach; iOS: `hooks-ios.js`).

What the hooks cover: `Cipher.getInstance/init/doFinal` (transform, opmode, key, IV, plaintext *and*
ciphertext), `SecretKeySpec`/`IvParameterSpec`/`GCMParameterSpec`, `PBEKeySpec` + `SecretKeyFactory`
(KDF inputs), `Mac` (the signature key and the exact signed bytes), X509/PKCS8 key specs, and
BoringSSL `EVP_{En,De}cryptInit_ex` for crypto that never touches Java (Flutter, Cronet, native SDKs).
iOS: `CCCrypt`, `CCCryptorCreate[WithMode]` + `Update`, `CCHmac`, `CCKeyDerivationPBKDF`,
`SecKeyCreateEncrypted/DecryptedData`, in-app OpenSSL. `CONFIG` at the top of each file tunes stack
traces (they name the class to open) and the noisy hooks.

Keep it as brief as possible: attach, drive the one flow you need, take the key, detach. Leaving an
agent attached for a whole session is what gets you detected and what makes your traffic look unlike a
real client's.

## When frida is detected or unavailable

In this order: patch the client (`patch-the-client.md`) → attach *after* startup checks (`-n` instead of
`-f`) → renamed `frida-server` on a non-default port → `frida-gadget` inside a repacked APK →
`objection --gadget <package> explore` for a single value. If all of that is a fight, the app is telling
you to go back to the proxy-side route.

## Confirming a captured key

`Cipher.init` fires for local-storage crypto too, so the first key you see may not be the network one:
match it against the `transform` and the stack trace, and then **decrypt a captured request with it**.
A GCM key that verifies its tag is certain; CTR/CFB/OFB and NoPadding never fail loudly, so a wrong key
just yields noise — `crypto-cli.py` warns when the output isn't text.

If decryption suddenly stops working mid-session, suspect **key renewal** before anything else: check
the key log (`crypto-cli.py keys --session <sid>`) and pick the key whose timestamp precedes the
request.
