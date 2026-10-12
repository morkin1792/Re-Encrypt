# What's worth reporting from this work

Breaking the transport encryption is setup work, not a finding on its own. But the way you broke it
usually *is* one — and you already have the evidence. Log these as you go.

## Findings you can prove with what you already have

| What you found | Why it matters | Proof you already have |
|---|---|---|
| **Hardcoded symmetric key** in the artifact | every install shares it; anyone with the APK can decrypt and forge traffic, so the "encryption" adds no confidentiality against a client-side attacker | the literal + a captured request decrypting with it |
| **Key derived from a shipped password** with a fixed salt | same as above, one KDF step removed | the derivation reproduced from the shipped inputs |
| **ECB mode** (repeated 16-byte blocks) | leaks plaintext structure; equal blocks are visible, and blocks can be cut-and-pasted between messages | the repeated-block analysis + a decrypted sample |
| **Fixed / reused IV** | with CBC, equal prefixes leak; with CTR/GCM, keystream reuse breaks confidentiality outright and forgery becomes possible | the constant prefix across samples |
| **GCM nonce reuse** | catastrophic for the mode: authentication key recovery | identical nonce in two messages under one key |
| **No integrity** (encryption only, no MAC, non-AEAD mode — e.g. a JWE-shaped token with an empty tag segment) | payloads can be modified/replayed; with CTR, flipping a chosen plaintext bit is exact and trivial | an edited request accepted by the server |
| **Replayable request** (no nonce/timestamp binding, or unchecked) | a captured request can be resent for effect | the same request accepted twice |
| **Padding oracle** — a corrupted last block gives a distinguishable "padding" error | the payload can be decrypted *and* forged with no key at all, ~256 requests per byte | the probe pair from `error-oracles.md`: last-block corruption → padding error, middle corruption → a different one |
| **Malleable payload** — flipping a middle byte is accepted | with CTR/CFB/OFB one flipped ciphertext bit flips exactly that plaintext bit, so chosen fields can be altered without the key | the flip probe returning the *original* response |
| **Deterministic ciphertext for the same input** | enables oracle/inference attacks and replay | byte-identical values across samples |
| **Embedded RSA private key** (or a hardcoded keypair used for a side channel) | anything encrypted to it is readable by anyone with the app; check how long it has shipped — a key unchanged across years of releases has been exposed for years | the key + a decrypted sample |
| **A key exchange the client can't authenticate** — the app accepts whatever public key it is handed, or the server accepts any client key | the whole encryption layer can be transparently intercepted (that is how you got in); it protects only against a passive network observer. When responses are encrypted to a *client-supplied* key, one substituted registration request decrypts every later response for that session | your own key-swap setup, working |
| **Encryption as the only access control** — server trusts the ciphertext's origin | once decrypted, all normal API testing applies; the "encryption layer" was the control | any authz/business-logic issue you then find |

## How to frame it

The impact is almost never "they use AES wrong" — it is what the weakness lets someone do: forge or
replay requests as another user, read intercepted traffic, or bypass a control the app assumed was
protected because the payload was opaque. Say that in business terms, once, and keep the crypto
detail in the technical description.

Note the client's perspective too: some clients treat client-side crypto as obfuscation and will rate
these informational. Ask, record the decision, and don't inflate. What is *never* informational is a
server-side issue you found **through** the decrypted channel — that's a normal finding.

## Don't stop at the crypto

The point of this skill is to reach the API. Once traffic is readable and editable, the encrypted
endpoints are ordinary HTTP: authz/IDOR, mass assignment, injection, business logic. Those are usually
the real findings, and they were hidden behind the blob — mention in the report that the encrypted
transport is what kept them from being found earlier (it is also why scanners saw nothing).
