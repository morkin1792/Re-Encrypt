# Body signatures, nonces and timestamps

Decrypting is half the job. If the app also signs the request, an edited payload is rejected and it
looks like your crypto is wrong. Settle this before you start testing.

## Recognising it

- A header or field carrying hex/base64 of exactly 20/32/48/64 bytes: `X-Signature`, `X-Sign`,
  `X-Hmac`, `X-Digest`, `Checksum`, `sign`, `mac`, `hash`.
- A `Hmac*` / `CCHmac` / `MessageDigest` reference in the artifact next to the crypto class.
- A nonce/timestamp field (`X-Nonce`, `X-Timestamp`, `ts`, `requestId`) — usually part of the signed
  input, and often independently checked for freshness/replay.
- The tell: an unmodified round-trip succeeds, a one-byte edit 401s/400s.

`ciphertext-analyze.py` lists these under **Integrity / freshness fields** with the digest size it
implies.

## Getting the signed input exactly right

The MAC covers a specific byte string, in a specific order. Guessing is slow; read it instead:

- **Best source — the runtime hook.** `Mac.doFinal` / `CCHmac` receives the *exact* signed bytes.
  `hooks-android.js` prints them (`signedInput`) together with the MAC key and the resulting MAC.
  Compare that string against the request you captured and the format is obvious.
- **Second best — the code.** Read the function that sets the header: it is almost always a
  concatenation of some of {method, path, query, timestamp, nonce, body (ciphertext *or* plaintext),
  a shared secret} with a separator (`\n`, `&`, `|`, or nothing).
- Confirm by recomputing the MAC of a **captured, unmodified** request and matching it byte for byte:
  ```bash
  printf '%s' "$SIGNED_INPUT" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$MACKEY
  ```
  Same value as the captured header ⇒ you have the recipe and the key. Nothing else proves it.

Watch for: signing the **ciphertext** vs the **plaintext** (both are common — the first means you
must sign *after* re-encrypting), lowercase vs uppercase hex, base64 vs hex, a trailing newline, and
URL-encoding applied before or after signing.

## Making your setup recompute it

Whatever proxy you use, the encrypt step must produce *both* the new ciphertext and the new MAC:

1. **Wrapper script** (works everywhere, recommended): a small script that takes the plaintext, does
   the encryption via `crypto-cli.py`, computes the MAC over the assembled input, and returns the
   full body (or writes the MAC where the proxy can pick it up). Use it as the Re:Encrypt
   *Encrypt Command*, or as the transform in an mitmproxy addon.
2. **Two patterns**: one for the payload, one whose "encrypt" step regenerates the signature header
   from the already-encrypted body. Simple when the MAC covers only the ciphertext.
3. **Proxy-level**: for a signature that covers the ciphertext only, an mitmproxy/Caido script hook
   that runs after re-encryption is the least fiddly place to put it.

If the timestamp/nonce is checked for freshness, regenerate it too — and note that a *replayable*
nonce or an unchecked timestamp is itself worth reporting.

## Related client-side gates you may hit at the same time

- **Certificate pinning** — different problem, same symptom class (nothing reaches the proxy). Solve
  it first; this skill assumes traffic is visible.
- **Anti-tamper / signature verification of the APK** — breaks the "patch the app" route; use runtime
  hooks or response rewriting instead (`key-exchange-mitm.md`).
- **Device binding** — the signed input may include a device id or an attestation token; reuse the
  captured value rather than inventing one.

Record in the profile (`integrity[]`) what is signed, where the key came from, and whether your
encrypt path handles it. `emit-reencrypt-config.py` refuses to call a profile complete while
`handled: false`, which is exactly the reminder you want before hours of confusing 401s.
