# Take the key from the key exchange (the preferred route)

When the key isn't in the artifact, **manipulate the handshake instead of instrumenting the app**. You
already sit in the middle: change what the two sides exchange and the key ends up in your hands.

Why this comes before any device work: no root, no `frida-server`, no repack, nothing for the app to
detect, and it keeps working after every restart because the client is untouched. It also beats
obfuscation and hardware-backed keystores, since you never look inside the app at all.

## The flow

1. **Find the handshake.** Filter proxy history for the first requests of a fresh session — `/init`,
   `/handshake`, `/keys`, `/register`, `/session`, or the login call. You are looking for a request or
   response carrying a **public key**, a **wrapped symmetric key**, or an **ephemeral key**
   (`ciphertext-analyze.py` flags a JOSE token with an *empty* wrapped-key segment as exactly this
   situation: the key is agreed elsewhere).
2. **Work out who encrypts to whom** — this one question decides the whole approach:

   | The exchange does this | Swap | You gain |
   |---|---|---|
   | client sends *its* public key; server returns a key encrypted to it | the **client's** key, in the request | the session key in the clear, from the response |
   | server publishes *its* public key; client encrypts to it | the **server's** key, in the response (or wherever the app reads it) | everything the client sends |
   | both sides send ephemeral public keys (ECDH/X25519) | **both** | both directions, via two derived secrets |

3. **Check the field is really manipulable.** Is the key signed? pinned to a hash in the app? does the
   same request sign something with the client's *private* key (a session id, a nonce) that you must
   re-sign with yours? Try it once by hand in Repeater before automating anything.
4. **Patch → persist → re-encrypt onward.** Substitute your key, recover the secret, **append it to a
   key log**, and re-encrypt whatever the other side must still be able to read using the *original*
   key you saved. The session continues normally and nothing downstream notices.
5. **Verify with an untouched request** before editing any payload: same response as without the proxy.

## Case A — the server hands the client a session key (hybrid)

Client posts a per-session public key, server replies with the symmetric key encrypted to it, every
body afterwards is symmetric:

```
app ──{client pub key, sig(session id)}──▶  [save the real pub key · substitute YOURS ·
                                             re-sign the session id with YOUR priv key]  ──▶ server
app ◀──{key encrypted to client pub}.{server sig}──  [decrypt with YOUR priv → append the key to the
                                                      key log → re-encrypt to the app's REAL pub key]  ◀── server
```

The server's signature over the key blob is untouched, so it still verifies. From then on every body
decrypts offline with the logged key — no further interception, no device involvement. This is the
answer to "the client keypair is generated fresh per session, so nothing can be precomputed".

Needs a small proxy extension, because there is logic (re-signing, two steps, writing the key out).

## Case B — RSA all the way, no session key

Some apps skip symmetric crypto entirely: the client registers its public key once and the backend
RSA-encrypts **every response** to it. Swapping that key buys *permanent* read access to that
direction — and makes you responsible for it for the rest of the session:

```
app ──{client pub key}──▶ [substitute YOURS] ──▶ server
app ◀── [decrypt with your priv · read/edit · re-encrypt with the app's ORIGINAL pub] ◀── RSA(response)
```

Every response must be re-encrypted before it reaches the client or the app breaks. That is exactly
what Re:Encrypt's **Patch proxy** does, so this case needs no extension at all:

| Step | How |
|---|---|
| one-off: swap the client's public key in the registration request | Burp match-and-replace on that field (static → static), or the extension if it is signed/dynamic |
| continuous: read **and** re-encrypt every response | a **response** pattern, engine **RSA**, `privateKey` = yours, `publicKey` = the app's original, **Patch proxy = on** |
| requests the client encrypts to the *server's* key | leave them, or swap that key too (A+B combined) when you need to edit them |

Save the app's original public key the first time you see it — the outbound leg is impossible without
it. And make the outbound encryption byte-compatible: `PKCS1` vs `OAEP` (SHA-1 vs SHA-256), and
chunking for bodies longer than one block (keysize − 11/42/66 bytes; `crypto-cli.py` chunks the same
way). Plaintext then shows up in the editor tab and in history for every message, which is usually
more convenient than a symmetric setup.

## Case C — ECDH / X25519

Nothing is transmitted to unwrap: each side derives the secret from its own private key and the peer's
public key, usually followed by HKDF. Be a real man in the middle on **both** legs:

```bash
crypto-cli.py keygen --alg x25519 --out keys/mitm.pem
# one derived key per leg — client-facing and server-facing
crypto-cli.py derive --priv file:keys/mitm.pem --peer-pub file:keys/client-real-pub.pem \
    --hkdf sha256 --hkdf-info utf8:<the app's context string> --length 32
crypto-cli.py derive --priv file:keys/mitm.pem --peer-pub file:keys/server-real-pub.pem --hkdf sha256
```

Get the KDF exactly right — the raw ECDH output is almost never the key. If a double swap is
impractical, patching the client's keypair collapses this back to Case A (`patch-the-client.md`).

## Case D — do the handshake yourself

If the exchange is client-initiated and not bound to device attestation, implement it in a script:
generate a keypair, play the handshake, recover the key. You own the key from the first byte and can
mint sessions on demand, with no interception at all.

Bonus, often a finding in itself: such a session carries **none** of the telemetry the real client sends
(device id, sensor/audit data, geolocation), which tells you whether a server-side decision is bound to
the recorded session context or only to the request. Point the script at the proxy so your own
handshakes still land in history.

## Implementing it in Burp

Don't start from scratch — use a request/response patcher skeleton such as **HttpHandlerSample**
(`github.com/morkin1792/HttpHandlerSample`). It registers a proxy handler *and* an `HttpHandler` for
every other tool, annotates modified messages ("modified by …", visible via the history dropdown
arrow), and leaves you four methods to fill in:

```java
shouldPatchRequest(request, toolType)          // filter: tool + method + URL contains the handshake
patchRequest(request, refModified)             // save the app's real pub key; substitute yours;
                                               // re-sign the session id/nonce with your private key
shouldPatchResponse(response, request, toolType)
patchResponse(response, request, refModified)  // decrypt the wrapped key with your priv key
                                               // append "<ts>: <key> <session-id>" to the key log
                                               // re-encrypt it to the app's real pub key
```

Practical notes that save an afternoon:

- **Shell out for the crypto** (`executeCommand("… crypto-cli.py dec --engine rsa --priv …")`) so the
  extension holds no crypto of its own and every step is debuggable on the command line.
- **Set `refModified[0] = true`** or your patched message is silently discarded.
- **Decide which tools to patch.** Filtering on `ToolType.PROXY` only means a handshake **replayed from
  Repeater/Intruder is not patched**, so its key never reaches the log — either mint keys by driving
  the app through the proxy, or widen the filter to accept `ToolType.REPEATER`; the skeleton already
  routes non-proxy tools through the same four hooks.
- **Log both keys and the session id** every time you substitute. When a later decrypt fails, that log
  is what tells you whether the key or the session was wrong.
- Exceptions are caught and written to the extension's **error log**, not shown to the app — watch it
  while you drive the first session, or a failing command just looks like "the swap didn't work".
- Keep the *filter* narrow (one method + one URL fragment). A patcher that fires on every request will
  eventually corrupt something unrelated and you will debug the wrong problem.

## Session keys have a lifecycle — log them, don't paste them

Keys expire and get renewed (often at a fraction of an advertised `exp`), so one session can own several
keys, and an old capture needs the key that was current *then*. Append-only, one line per key:

```
2026-09-01T14:28:50: pXk4qZDS3VLQPyPk832i350ykiEL1jOf bcd7c542-e126-40c1-a7d0-bf8069180c8f
<timestamp>          <key>                            <session id>
```

```bash
crypto-cli.py keys --key-log ./key --session <sid>          # every key that session had
crypto-cli.py dec --structure jwe --key-log ./key --session <sid> --in-file body.json
crypto-cli.py dec --structure jwe --key-log ./key --in-file raw-request.txt   # sniffs the sid itself
```

Mint a fresh key deterministically instead of waiting for one — restart the app through the proxy and
read the last line:

```bash
adb shell dumpsys window | grep mCurrentFocus      # don't kill a flow that is mid-way
adb shell am force-stop <package>
adb shell monkey -p <package> -c android.intent.category.LAUNCHER 1
sleep 12 && tail -1 ./key
```

**In-proxy key selection is "newest key", not "the right key".** A key file or key command handed to
Re:Encrypt sees only the payload, never the request headers, so it cannot pick a key by session id.
Keep one device/session live at a time; do session-accurate decryption offline with `--session`.

## Reversibility

Rewriting key-exchange traffic and swapping keys changes client state. Note what you patched (endpoint,
field, file), keep the app's original public key (you need it for the outbound leg anyway), and restore
the clean client when you're done.

## It is usually a finding too

If you could swap the key, the exchange is unauthenticated: the backend cannot tell your key from the
real client's, and in Case B anyone who can MITM a single registration request decrypts every later
response. Report it, with your working setup as the evidence (`crypto-weaknesses.md`).
