# Making it fail on purpose: error oracles

When the bytes are ambiguous and no candidate key works, stop guessing and **ask the implementation**.
Corrupt a ciphertext in one specific way and the error tells you what the code expected. Crypto
libraries are unusually talkative, and app error handling usually forwards their message verbatim.

Use this as a diagnostic when Step 3 (name the scheme) or Step 5 (prove it) is stuck — not as a first
move, and never as a fuzz run. Ten surgical probes answer more than ten thousand random ones.

## Client-side first — it is free and safe

**Corrupt a captured *response* and let the app fail.** Nothing reaches the server, so there is no
footprint on the target at all, and the client is the side whose crypto you are trying to understand.

```bash
python3 "$SKILL"/scripts/error-probe.py res.txt --response-mode --field data --out probes/
# serve each probes/probe-*.txt body to the app: Burp match-and-replace on the response, or
# response interception, then read the error:
adb logcat -c && adb logcat | grep -iE 'exception|crypt|cipher|pad|tag|iv |key|at [a-z][a-z0-9.]*\.[A-Z]'
# hybrid/WebView app: chrome://inspect → Console (you also get the file and function)
```

What the message tells you:

| Error the client throws | What it proves |
|---|---|
| `IllegalBlockSizeException: Input length must be multiple of 16` | padded **block** mode, and the number *is* the block size (16 ⇒ AES) |
| `BadPaddingException` / `pad block corrupted` | CBC/ECB + PKCS#5/7 **and no integrity check** — your edits will be accepted |
| `AEADBadTagException` / `MAC check failed` | AEAD (GCM/CCM) or encrypt-then-MAC: stop trying to tamper, get the key |
| `InvalidAlgorithmParameterException: Wrong IV length: must be 16 bytes` | the IV comes from the message and is length-checked ⇒ `structure=iv_ct`, `ivLength=16` |
| `InvalidKeyException: Invalid AES key length: N bytes` | the app just told you its key size |
| a transform string (`AES/CBC/PKCS5Padding`) in the message | the entire scheme, for free |
| `JSONException` / `Unexpected token` after *no* crypto error | it decrypted your garbage: **no integrity**, and a stream mode or `NoPadding` |
| a stack trace naming app classes | **the class to open in jadx** — often worth more than the error itself |

A wrong-key decrypt that produces *nothing* (empty string, silent catch) is itself a signal: some
libraries — CryptoJS among them — return an empty result rather than throwing, which is why apps
"just show a blank screen" instead of an error.

## Server-side second — informative, but intrusive

Corrupting a *request* asks the backend the same questions, and additionally reveals **whether the
server checks integrity before it decrypts**. It is opt-in for a reason: malformed traffic lands in
the target's logs, may trip fraud/WAF monitoring, and a storm of it looks like an attack.

```bash
# dry run: writes the probe messages + PROBES.md, sends nothing
python3 "$SKILL"/scripts/error-probe.py req.txt --field data --out probes/

# send, through the proxy so every probe is auditable, one per second, capped
python3 "$SKILL"/scripts/error-probe.py req.txt --field data --send \
    --proxy http://127.0.0.1:8080 --header 'X-Engagement: <marker>' --delay 1.0 --max 10
```

Rules that keep this proportionate:

- **Through the proxy, always**, with the engagement's identifying header — the same auditability rule
  as everything else you send.
- **Stop at the first informative class.** You do not need the full set; three probes usually settle it.
- **Never on a destructive endpoint.** Pick a read-only one (a balance/list/profile call). A corrupted
  transfer request may still be *partially* processed by a badly-written backend.
- One session, one device, `--delay` ≥ 1s, and `--max` low. If the app or the API starts rejecting the
  whole session, you have gone too far — restart the app and back off.

The classifier groups responses by (status, body) and reads the scheme off which classes exist:

| Observation | Conclusion |
|---|---|
| every probe → the same response | the server rejects **before** decrypting (length/MAC/schema first), or collapses all errors into one. No oracle; go back to getting the key |
| `truncate-1` is its own class | the length is validated separately ⇒ padded block mode |
| `flip-last-byte` gives a *padding* error while `flip-middle-byte` gives another | **padding oracle** — decryption and forgery without the key, and a finding |
| `flip-middle-byte` returns the **original** response | that region isn't authenticated (and with CTR/CFB you just flipped exactly those plaintext bits) |
| `invalid-encoding` is its own class | the outer encoding is decoded before any crypto — fix that layer first |
| a 500 with a stack trace | the scheme, and often the server-side class names |

Collected the results elsewhere (e.g. sent the probe files through the proxy MCP because the edge is
HTTP/2-only)? Feed them back as JSON:

```bash
python3 "$SKILL"/scripts/error-probe.py --classify results.json    # {"probe-name": {status, sha1, excerpt}, "baseline": {…}}
```

## What each probe is asking

| Probe | Question |
|---|---|
| `random-same-length` | the "wrong key but well-formed" baseline every other class is compared against |
| `truncate-1` | is the length validated? what is the block size? |
| `flip-last-byte` | padding vs integrity — the single most informative probe |
| `flip-middle-byte` | is the middle authenticated? is the mode malleable (CTR/CFB/OFB)? |
| `flip-first-byte` | are the leading bytes an IV (`iv_ct`) rather than ciphertext? |
| `truncate-block` / `append-block` | separate length checks from content checks |
| `swap-blocks` | block independence: reordered plaintext ⇒ ECB; two corrupt blocks ⇒ CBC |
| `invalid-encoding` | does the decode layer run and validate before the crypto? |
| `empty` | is the field even required? |

## Where the answers go

Straight into the profile and the next command: a block size and a "length is validated" tell you
`structure` and `padding`; an IV-length error fixes `ivLength`; a tag error moves you to `iv_ct_tag` +
GCM and tells you to stop tampering; "it decrypted my garbage" means a stream mode and that editing
will work once you have the key. Then go back to `crypto-cli.py solve` with the parameter space cut
down, or to Step 4 for the key.

Two of these observations are **findings**, not just diagnostics — a distinguishable padding error, and
a payload whose middle can be flipped without rejection. Record them per `crypto-weaknesses.md` while
you are here; the evidence is the probe pair you already sent.
