# Recognizing the scheme from the wire

Goal: from a handful of captured samples, name the cipher family, the mode, the **structure** (how
IV/tag/salt are packed with the ciphertext) and the outer encoding. `ciphertext-analyze.py` does the
mechanical part; this is how to read its output and decide.

## Decide in this order

1. **Is it encrypted at all?** Decode the outer layer first. If it decodes to printable text, JSON,
   protobuf-ish bytes or gzip (`1f 8b`), it is *encoded/compressed*, not encrypted. A 3-segment
   `eyJ...` token is a **JWT: signed, not encrypted** — the payload is readable base64url; you need
   the signing key only to modify it.
2. **Outer encoding.** Base64 / Base64URL (`-_` and no `+/`) / hex / raw bytes / percent-encoded on
   top of one of those. Get this right before anything else — a wrong outer decode looks exactly
   like a wrong key.
3. **Structure, from magic and arithmetic** (on the *decoded* bytes):
   - 5 dot-separated segments → **JWE compact**: header · wrapped key · IV · ciphertext · tag. Read
     the header JSON: `alg` tells you how the CEK is wrapped, `enc` gives the content mode
     (`A256GCM` → GCM, `A256CBC-HS512` → CBC, and non-standard values like `A256CTR` do appear).
     Then check the *segments*, because hand-rolled "JWE" is common and the header often lies:
     an **empty wrapped-key segment** means the key is not in the message at all — it came from a
     key exchange, and that exchange is where you take it (`key-exchange-mitm.md`). An **empty or
     blank tag segment** (a single space counts) means there is no authentication tag: the body is
     encrypted but not authenticated, so the server will accept your edits, and `alg: RSA-…` on such
     a token is decoration, not a description of how the key travels.
   - starts with `Salted__` → **OpenSSL `enc`**: 8-byte magic + 8-byte salt + ciphertext, key and IV
     derived per message from a *password*.
   - length % 16 == 0 → block mode with padding (CBC/ECB). Repeated 16-byte blocks ⇒ **ECB or a
     fixed IV** — a finding by itself.
   - (length − 16) % 16 == 0 → **IV prepended** (`iv_ct`), the overwhelmingly common layout.
   - length not block-aligned → stream-ish (**CTR/GCM/CFB/OFB**); check the head for a 12/16-byte
     nonce and the tail for a 16-byte GCM tag (`iv_ct_tag`).
   - length is exactly 128/256/384/512 bytes (or a multiple) → **raw RSA blocks** of a
     1024/2048/3072/4096-bit key. A multiple means the app chunks long bodies.
4. **Cross-sample tells** (why you collect 3+ samples of one endpoint):
   - constant 16-byte prefix ⇒ fixed IV, not a random one.
   - byte-identical values for the same input ⇒ deterministic encryption; replay is likely.
   - all lengths block-aligned ⇒ block mode; none ever aligned ⇒ stream mode.
   - JWE: if the **wrapped key segment repeats**, the CEK is per *session* — capture it once and the
     whole session opens. If it changes per message, you need to unwrap it (key swap) or hook it.

## What the artifact tells you that the wire can't

The transform string in the binary is the cheapest ground truth there is: `AES/CBC/PKCS5Padding`,
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` name mode and padding exactly. Java/Kotlin apps almost
always contain one. Cross-check it against the wire arithmetic; when they disagree, believe the
sample (apps ship dead code).

Also worth reading before touching the wire again: whether the app uses `AndroidKeyStore` (key bytes
may not exist in Java at all — hook the object), whether a KDF is present (the literal you found is
a *password*, not a key), and whether an RSA public key is embedded or fetched (that decides
static-vs-key-swap).

## The shape catalogue — ordered by how often you'll meet it

Almost all app traffic crypto falls into one of these. Identify the shape and the key route follows.
The **frequency** column is a prior, not a rule — start your hypotheses at the top:

| Shape | How common | Wire tell | Key route |
|---|---|---|---|
| **Symmetric, static key** | **most** | `iv_ct`/raw blob; same arithmetic every time; captures from months ago still decrypt | read it out of the artifact (`static-key-hunt.md`) |
| **Symmetric, derived key** | common | as above, but no key literal exists — a password/salt/iteration count does | reproduce the KDF exactly |
| **Symmetric, session key** | common | same shape, but ciphertexts stop decrypting after re-login or renewal | take it from the exchange (`key-exchange-mitm.md`); keep a key log |
| **Hybrid: RSA wraps a symmetric key** | common | JWE with a populated wrapped-key segment, **or two fields where one is exactly the modulus size** (128/256/384/512 B) and the other is longer | swap the public key and unwrap it yourself; or read the wrapped key with a hardcoded private key if the app ships one |
| **Key delivered by the server to the client's key** | common | a handshake (`/init`, `/keys`, `/register`) or a login-response field holding a wrapped key | swap the **client's** public key → the server hands you the key in the clear |
| **Key from a shared secret + per-request nonce** | occasional | a server nonce/timestamp in the request; the key is never transmitted | reproduce the derivation (usually HKDF/HMAC over the nonce) |
| **ECDH / X25519 agreed key** | occasional | both sides publish an ephemeral public key; no wrapped key anywhere; `X25519`/`ECDH`/HKDF in the code | swap **both** legs, derive both secrets (`crypto-cli.py derive`) |
| **Asymmetric only — RSA end to end** | **least** | every payload length is a multiple of the modulus size; short bodies only | extract the private key if it ships, else swap the key and re-encrypt **every** message in that direction |
| **Encoding/compression only** | — | decodes to text, gzip magic, protobuf-ish | not encryption — stop here |
| **Signed, not encrypted** | — | JWT (3 segments, readable payload), or plaintext + a MAC header | nothing to decrypt; `integrity-and-signatures.md` |
| **Layered** | — | a JWE inside a field of an already-encrypted body, base64 of base64 | peel one layer at a time; each layer may use a different key |

### Why the ordering looks like that

**RSA end to end is rare because it is slow and size-limited** — one modulus-sized block per operation,
so a body has to be chunked and every request costs a public-key operation on both sides. Apps that
start there usually move to a hybrid. Two consequences worth internalising:

- **If you see RSA, look for a symmetric key next to it.** An RSA-sized blob in one field and a longer
  blob in another is almost always "wrapped key + payload", not two encrypted payloads.
- **If RSA really is the whole scheme**, the swap has to stay in place for the whole session, because
  you become the only one who can read that direction — that is the continuous-patching case in
  `key-exchange-mitm.md`, and it is the one shape where you cannot just grab a key and walk away.

Conversely, a hardcoded symmetric key is the most common thing you will find, which is why rung 1 of
the ladder is always worth the ten minutes: the most likely answer is also the cheapest to test.

If a sample doesn't fit any row, don't force it — the fastest disambiguation is a parameter sweep:

```bash
crypto-cli.py solve --key-candidates <work>/triage/keys.txt --in-file <work>/samples/ct1.txt
crypto-cli.py solve --key-log <work>/keys/key --expect '"cpf"' --in-file <work>/samples/ct1.txt
```

It tries every plausible encoding × structure × mode × IV convention × key interpretation, ranks by
how text-like the output is, and prints the exact command that reproduces the winner. Use `--expect`
with a string you know is in the plaintext when you want an unambiguous answer.

And if the sweep comes back empty, make the implementation answer instead of guessing further:
`error-oracles.md` (corrupt a captured response, read the client's exception — no traffic to the
target, and the error usually names the block size, the IV length, the padding, and the class doing
the work).

## Common trip-ups worth checking early

- A **32-character** key literal is usually 32 UTF-8 bytes (AES-256), not 16 hex-decoded bytes. Try
  both — `--key utf8:…` and `--key hex:…`.
- The IV is frequently *not* random: all-zero, the first 16 bytes of the key, the key itself, or a
  fixed ASCII string in the code.
- CBC where only the first block is garbage ⇒ right key, wrong IV. Garbage after a readable first
  block ⇒ wrong IV *and* you're not in CBC.
- Java's `AES/CFB` is CFB128; some libraries default to CFB8. If CFB output looks byte-shredded,
  switch the segment size.
- Base64 inside a form body arrives with `+` turned into spaces; put them back before decoding.
- Some apps encrypt only *part* of the body, or double-encode (base64 of base64). Try one nested
  decode before concluding "weird cipher".
- Responses often use a different key or structure than requests — and a different **wrapper**: a
  request may be `{"data":"<blob>"}` while the response is a bare JSON string `"<blob>"`. Verify each
  direction separately.
- The plaintext can be **compressed**: decrypting yields `{"data":"<base64(deflate(json))>"}` or raw
  zlib bytes rather than JSON. `crypto-cli.py` inflates that automatically (`--deflate` to produce it);
  if you see high-entropy "plaintext" that starts `78 9c`, that's what happened — not a bad key.
- Apps ship **more than one crypto model**, selected by a config flag or a server response (e.g. an
  RSA+CTR path today and an X25519/HKDF+GCM path waiting behind a setting). Confirm from live traffic
  which one is active, and re-check if a header value ever changes — a swap invalidates the whole
  setup, key route included.
- The same app may use a *second, unrelated* key for a side channel (a hardcoded keypair for one
  helper, the session key for everything else). Don't assume the first key you find is the one on the
  path you're testing.
