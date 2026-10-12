---
name: decrypt-app-traffic
description: Work out how a mobile/desktop app encrypts its own HTTP traffic, get the key, and produce a working decrypt/re-encrypt setup — including the Re:Encrypt (Burp) configuration. Use this when an app's requests or responses are an opaque blob instead of readable JSON, when the user says "this app encrypts its traffic", "the body is encrypted", "how do I decrypt this app's requests", "set up Re:Encrypt", "find the AES/RSA key in this APK/IPA", or before testing an app whose payloads aren't plaintext. Takes a directory of APK/IPA artifacts and, if a proxy MCP is connected, the captured traffic.
argument-hint: "[<apps-dir>] [--work <dir>] [--no-static] [--no-device]"
---

# Decrypt app traffic

Step 0 of testing an app that encrypts its own payloads: turn an opaque blob into readable,
**editable** traffic. Nothing else — no fuzzing, no authz testing, no reporting — is worth doing
until a captured request decrypts and a re-encrypted one is accepted.

`$ARGUMENTS` may contain: a directory of `.apk` / `.ipa` artifacts, `--work <dir>` (where output
goes, default `./crypto`), `--no-static` (skip artifact analysis), `--no-device` (no device work at all).

**Two rules that make this work:**
- **Prove, don't guess.** A hypothesis becomes a fact only when a *captured* sample decrypts to
  plaintext you recognise. Tool output, entropy, "looks like AES" — leads, not conclusions.
- **Only test apps you're authorized to test.** Extracting keys and decrypting traffic is
  engagement work; confirm scope before touching a real device or a live host. Inside the pentest
  toolkit, the `pentest-core` scope/safety rules and action policy apply unchanged.

## Step 0 — Set up and read what you need

1. **Resolve this skill's own directory once** — the scripts live next to this file, not in the
   project you are testing:
   ```bash
   SKILL=<the directory containing this SKILL.md>      # its path is shown when the skill loads
   # no path? find it by a file that exists only here (works whatever the folder is named):
   SKILL=$(cd "$(dirname "$(dirname "$(find . "$HOME/.claude" "$HOME/.codex" -maxdepth 6 \
       -name crypto-cli.py 2>/dev/null | head -1)")")" && pwd)     # absolute, survives any cd
   ls "$SKILL/scripts"     # must list crypto-cli.py, crypto-triage.py, ciphertext-analyze.py, …
   ```
   Every command below is written with `$SKILL` — keep it set (or substitute the absolute path).
2. `mkdir -p <work>/{samples,keys,evidence}`. Everything below lands there; the deliverable is
   `<work>/profile.json` + `<work>/RUNBOOK.md`.
3. Read `$SKILL/references/recognize-scheme.md` now. Read the others on demand:
   `static-key-hunt.md` · `js-crypto-defaults.md` (any JS/WebView app — read it before trusting a
   literal) · `key-exchange-mitm.md` · `patch-the-client.md` · `runtime-key-capture.md` ·
   `error-oracles.md` (when the scheme won't resolve) · `integrity-and-signatures.md` ·
   `reencrypt-config.md` · `no-plugin-workflows.md` · `crypto-weaknesses.md`.
4. Check what you have: artifacts in the given directory; a proxy MCP (Burp: proxy-history ops);
   a device (`adb devices -l`); a python crypto lib or `openssl`
   (`python3 "$SKILL"/scripts/crypto-cli.py selftest` tells you in one line).
5. **Look for prior work on this app first** — an earlier engagement folder, notes, a key log, a
   protocol write-up. These schemes change slowly (hardcoded keys and handshake shapes survive for
   years), and a five-minute read can replace the whole hunt.
6. If traffic isn't reaching your proxy yet, that comes first — pinning/CA/routing work is a
   different job (in the pentest toolkit: the `pentest-mobile` interception setup). This skill
   assumes you can see the encrypted requests.

## Step 1 — Triage the artifacts  (skip with `--no-static`)

```bash
python3 "$SKILL"/scripts/crypto-triage.py <apps-dir> --out <work>/triage
```

Read the report, not the whole APK. It gives you: package/bundle id, framework and network stack,
every crypto API the app references (with the transform strings — `AES/CBC/PKCS5Padding` names the
mode *and* padding for free), embedded PEM keys (written out as files), ranked key-material
candidates, the classes to open first in jadx, and the hosts to expect.

Then, and only then, open the 2–5 classes it named (`jadx`, or the JS bundle for RN/Cordova) to read
the actual encrypt path. Per `references/static-key-hunt.md` — and for a JS/WebView app,
`references/js-crypto-defaults.md` first: the library's defaults *are* the scheme, and a string key
in CryptoJS is a passphrase, not a key.

## Step 2 — Get real samples and locate the ciphertext

Capture a **fresh session from its very first request** — force-stop the app and re-launch it through
the proxy. The opening requests are where a key exchange lives, and they are what makes rung 2 of Step
4 possible; a history that starts mid-session hides the most useful thing in it.

Then collect 3+ samples of the *same* endpoint — cross-sample structure is the strongest signal you get.

- **Proxy connected:** pull the history for the app's hosts (Burp MCP: `get_proxy_http_history`,
  or `get_proxy_http_history_regex` to filter), and save each raw request to `<work>/samples/`. Save
  the session's first few requests separately as `<work>/samples/handshake-*.txt`.
- **No proxy:** a HAR export, a saved raw request, or drive the app once and grab it from the device.

```bash
python3 "$SKILL"/scripts/ciphertext-analyze.py <work>/samples/ > <work>/ANALYSIS.md
```

It locates the encrypted field(s), ranks scheme hypotheses with the exact engine params and CLI
command for each, flags integrity/nonce fields, and — across samples — tells you whether the mode is
block or stream, whether the IV is fixed, whether a key is reused, and for JWE which segment repeats.

**Read the handshake requests yourself as well**, with one question in mind: does either side send a
public key, a wrapped key, or an ephemeral key? If so, that is where the key comes from and Step 4
rung 2 applies — see `references/key-exchange-mitm.md`.

## Step 3 — Name the scheme

From Step 1 + Step 2, commit to a hypothesis: cipher family, mode, structure (raw / IV+CT /
IV+CT+tag / OpenSSL `Salted__` / JWE), outer encoding, and padding. `references/recognize-scheme.md`
has the decision tree and the "this isn't encryption at all" checks (base64, gzip, JWT, protobuf).

Start from the **most common** shapes: a static symmetric key, then a derived one, then a session key
from an exchange; RSA end-to-end is the rarest (too slow, too size-limited) — so when RSA shows up,
expect it to be *wrapping* a symmetric key rather than carrying the body. The catalogue is ordered by
frequency for that reason, and the analyzer calls out a modulus-sized field sitting next to a longer
one as "wrapped key + payload".

**Still ambiguous?** Make it fail on purpose and read the scheme off the error — start with the
client-side variant, which sends nothing to the server:

```bash
python3 "$SKILL"/scripts/error-probe.py <work>/samples/res1.txt --response-mode --field data \
    --out <work>/probes/          # then serve a probe back to the app and read logcat / the console
```

`references/error-oracles.md` maps each library exception to a scheme fact (block size, IV length,
padding vs AEAD, "it decrypted my garbage"), and covers the intrusive server-side variant with its
rules. A stack trace in that error usually names the class to open in jadx, which often ends the
hunt on its own.

## Step 4 — Get the key

The scheme is easy; the key is the job. **Work this ladder in order. Do not skip a rung because a
lower one looks quicker — go down only when the rung above is genuinely impossible**, and say which
rung you used and why.

1. **Is the key in the app?** Read it out of the artifact and test it immediately — a literal, a
   resource, an embedded PEM, or a KDF you can reproduce (salt + iterations + digest).
   → `static-key-hunt.md`, `js-crypto-defaults.md`. *Cost: minutes, nothing touched.*
2. **Can the requests give it to you?** Analyze the first requests of a fresh session and look for a
   key exchange you can manipulate: substitute your own public key in the handshake and the server
   hands you the session key — or, for an RSA-only app, decrypt-and-re-encrypt each message with
   Re:Encrypt's *Patch proxy*. → `key-exchange-mitm.md`. *Cost: a match-and-replace or a small proxy
   extension. No root, no agent, nothing for the app to detect, and it survives every restart.*
3. **Can you change the app?** Replace the generated keypair with one you own (permanent, then the
   traffic decrypts offline), or add a single line that writes the key out. → `patch-the-client.md`.
   *Cost: repack + resign, and a resigned app can trip integrity checks.*
4. **Only if none of the above worked: hook the process.** → `runtime-key-capture.md`. *Cost: an agent
   on the device, root or a gadget, and it is noisy and detectable — which is why it is last, not
   because it is hard. Attach, take the value, detach.*

Rung 2 is the one people skip and shouldn't: a key that "only exists at runtime" is usually still
*negotiated over HTTP*, and the negotiation is in your proxy already. Read the handshake before
concluding you need instrumentation.

If the app ships an embedded RSA **private** key, try it before anything else — sometimes there is no
work to do at all. Keep captured keys in an append-only key log (`<ts>: <key> <session-id>`), not
pasted into a config: session keys get renewed, and an old capture needs the key that was current then.

```bash
python3 "$SKILL"/scripts/crypto-cli.py keys --key-log <work>/keys/key --session <sid>   # what that session had
python3 "$SKILL"/scripts/crypto-cli.py keygen --alg rsa --out <work>/keys/mitm.pem      # a pair for a key swap
python3 "$SKILL"/scripts/crypto-cli.py derive --priv file:<work>/keys/mitm.pem \
    --peer-pub file:<work>/keys/peer-pub.pem --hkdf sha256                     # ECDH/X25519 schemes
```

## Step 5 — Prove it offline (hard gate)

```bash
# you have a hypothesis and a key -> test it directly
python3 "$SKILL"/scripts/crypto-cli.py dec --mode CBC --structure iv_ct --key file:hex:<work>/keys/aes.key \
    --in-file <work>/samples/ct1.txt

# unsure of the parameters, or several candidate keys -> let it search
python3 "$SKILL"/scripts/crypto-cli.py solve --key-candidates <work>/triage/keys.txt \
    --expect '"cpf"' --in-file <work>/samples/ct1.txt
```

You must see plaintext you recognise. `solve` sweeps encoding × structure × mode × IV convention ×
key interpretation and prints the command that reproduces the winner; it is also the fastest way to
rule a candidate key out. If you drive it by hand instead, change **one** variable at a time —
structure, then mode, then encoding, then key format (a 32-char literal is more often 32 UTF-8 bytes
than hex). GCM is the friendliest case: the tag verifies, so a right key is unambiguous. CTR/CFB/OFB and
NoPadding never fail loudly — a wrong key yields noise, and the tool says so.

Do not proceed on a partial result (readable first block, garbage after ⇒ wrong IV; garbage first
block, readable after ⇒ wrong IV with CBC; all garbage ⇒ wrong key or wrong structure). If it worked
earlier and stopped, suspect **key renewal** before touching any other parameter.

If nothing decrypts and you are no longer sure *what* is wrong, get the implementation to tell you:
`references/error-oracles.md` (client-side probes first — free and invisible to the target).

## Step 6 — Handle integrity and freshness

If the analyzer flagged a signature/HMAC/nonce/timestamp field, deal with it now — otherwise every
edit you make will come back 401/400 and you'll blame the crypto. Per
`references/integrity-and-signatures.md`: work out exactly what is signed, get the MAC key (it usually
travels with the session key — same exchange, same capture), and make your encrypt step recompute it.

## Step 7 — Write the profile and emit the setup

Write `<work>/profile.json` per `$SKILL/assets/crypto-profile.schema.json` (see `$SKILL/assets/examples/` for a
static-key, a JWE/hybrid, a rotating-key + signed-body, and a handshake-session-key profile), then:

```bash
python3 "$SKILL"/scripts/emit-reencrypt-config.py <work>/profile.json --out <work> \
    --cli-path "$SKILL/scripts/crypto-cli.py"
```

You get `RUNBOOK.md` (field-by-field Re:Encrypt setup, the equivalent custom-command pair, and every
open gap) and `reencrypt-config.json` (the proposed import format — the machine-readable record
today, one-click import when Re:Encrypt supports it). Configure the extension from the runbook per
`references/reencrypt-config.md`; without Burp, use `references/no-plugin-workflows.md`.

## Step 8 — Verify live, then hand over

0. **Prove the transport before blaming the crypto.** Replay one *captured, unmodified* request and
   get the original response first. Match what the client does: HTTP version (some edges drop
   HTTP/1.1 outright), and every header the API requires (`accept-language`, app/session/correlation
   ids). A 400 from a missing header looks exactly like a broken re-encryption.
1. Round-trip an **unmodified** payload through the proxy: same response as the original ⇒ your
   encrypt path is correct.
2. Change one harmless value and confirm the server acted on it ⇒ the whole chain works, signature
   included. Save both request/response pairs into `<work>/evidence/`.
3. Update `profile.json` (`verified.roundTrip`) and re-run the emitter.
4. Report the crypto weaknesses you found on the way (hardcoded key, ECB, fixed IV/nonce reuse,
   client-side-only protection) — `references/crypto-weaknesses.md`.
5. Tell the user, in this order: what the scheme is, where the key comes from, what they must run or
   click, what is verified, and what is still assumed. Keep the profile alive — when keys rotate or
   the app updates, only Step 4/5 need redoing.

If you get stuck, say precisely which step failed and what you ruled out. "Wrong key" and "wrong
structure" need different next moves, and a wrong guess here wastes hours.
