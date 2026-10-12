# Re:Encrypt Skill — `decrypt-app-traffic`

An agent skill (Claude Code / Codex) for the step *before* you can test an app that encrypts its own
HTTP payloads: **work out how the encryption works, get the key, and produce a working
decrypt/re-encrypt setup**.

Give it a directory of `.apk` / `.ipa` files — and, if a proxy MCP is connected, the captured
traffic — and it will:

1. triage every artifact for crypto APIs, embedded keys, key candidates, framework/network stack;
2. locate the encrypted field in real requests and rank what the scheme can be;
3. route the key hunt down a fixed ladder — **(1)** key shipped in the app › **(2)** key taken from the
   handshake in your proxy (swap a public key; no root, no agent, nothing to detect) › **(3)** patched
   client › **(4)** runtime hooking, only if nothing above works;
4. **prove** the hypothesis by decrypting a captured sample;
5. deal with body signatures / nonces so edited requests are accepted;
6. emit `RUNBOOK.md` (field-by-field Re:Encrypt setup + equivalent CLI commands) and
   `reencrypt-config.json` (the proposed import format).

It is self-contained: nothing here requires the Re:Encrypt Burp extension, and the same
`crypto-cli.py` drives mitmproxy, Caido or plain curl (`references/no-plugin-workflows.md`). When
Re:Encrypt *is* in play, the skill produces its exact configuration.

## Install

`skills/decrypt-app-traffic/` is **self-contained — copy it into `.claude/skills/` and it works** in
any Claude Code session opened in that directory. Nothing inside refers to this repository.

```bash
./install.sh /path/to/project     # copy into <project>/.claude/skills/  (+ runs a self-check)
./install.sh --user               # copy into ~/.claude/skills/ (every project)
./install.sh --link /path/to/proj # symlink instead, so edits here take effect immediately
# or by hand:
cp -r skills/decrypt-app-traffic <project>/.claude/skills/
```

Start a **new session** in that directory afterwards — skills are discovered at session start. Keep
the folder named `decrypt-app-traffic`: Claude Code matches the directory name against `name:` in the
frontmatter, so a rename means editing that field too (nothing else inside depends on the name).

Or as a plugin: `/plugin marketplace add <path-to-this-directory>` then install
`re-encrypt-skill@re-encrypt-skill`.

**Codex**:

```bash
codex plugin marketplace add <path-to-this-directory>
codex plugin add re-encrypt-skill@re-encrypt-skill
```

Then start a session and say what you want — *"the requests from these APKs are encrypted, figure out
how"* — or invoke it by name (`/decrypt-app-traffic apps/`). No app handy? Build three fixture apps
with real encrypted traffic, one per rung of the key ladder:

```bash
python3 skills/decrypt-app-traffic/testdata/make-fixtures.py /tmp/skilltest --answers
```

## Layout

```
skills/decrypt-app-traffic/
  SKILL.md                       the workflow (steps 0–8)
  references/
    recognize-scheme.md          wire evidence → cipher/mode/structure; the "not encryption" checks
    static-key-hunt.md           keys in the artifact, per stack; reproducing a KDF
    js-crypto-defaults.md        CryptoJS/forge/sjcl/WebCrypto defaults (a string key is a passphrase),
                                 and using the app's own library as the oracle
    key-exchange-mitm.md         PREFERRED route for negotiated keys: manipulate the handshake —
                                 hybrid session-key delivery, RSA-only continuous patching (Patch
                                 proxy), ECDH double swap, or running the handshake yourself; plus
                                 the Burp patcher skeleton and the key-log convention
    patch-the-client.md          replace the client's keypair / add a log line / repack & sign
    runtime-key-capture.md       hooking, and why it's the last resort (noisy, detectable, needs an agent)
    integrity-and-signatures.md  HMAC/nonce/timestamp: find the signed input, recompute it
    reencrypt-config.md          profile → Re:Encrypt patterns, engine params, troubleshooting
    no-plugin-workflows.md       mitmproxy addon, CLI loops, CyberChef
    crypto-weaknesses.md         what of this is report-worthy, and how to frame it
  scripts/
    crypto-triage.py             stdlib-only APK/IPA crypto triage (AXML + DEX + Mach-O readers)
    ciphertext-analyze.py        locate the ciphertext in HTTP/HAR; rank scheme hypotheses
    crypto-cli.py                AES/RSA/JWE worker + `solve` (parameter sweep), `keys` (key logs),
                                 `keygen`/`derive` (key-swap pairs, ECDH+HKDF); custom-command ready
    frida-run.py                 last-resort hooking runner; keeps a live key file + key log
    emit-reencrypt-config.py     crypto profile → RUNBOOK.md + reencrypt-config.json
    oracle/js-crypto-oracle.js   decrypt/encrypt with the app's OWN JS library (CryptoJS, sjcl)
    frida/hooks-android.js       Cipher/SecretKeySpec/Mac/RSA + BoringSSL EVP hooks
    frida/hooks-ios.js           CCCrypt/CCCryptorCreate/CCHmac/SecKey* hooks
  testdata/make-fixtures.py      three fake apps + real encrypted traffic, one per ladder rung
  assets/
    crypto-profile.schema.json   the profile the agent writes (the skill's real output)
    reencrypt-config.schema.json proposed Re:Encrypt import format (1:1 with CapturePattern/Config)
    examples/*.profile.json      static-key AES-CBC · CryptoJS passphrase (OpenSSL envelope) ·
                                 RSA+JWE hybrid · RSA-only with Patch proxy · rotating GCM key +
                                 HMAC body · handshake-derived session key with a key log
```

## Requirements

Nothing mandatory beyond Python 3.9+. Everything degrades gracefully:

| Want | Needs | Without it |
|---|---|---|
| artifact triage | nothing (stdlib) | — |
| identity from a real tool | `aapt` / `apkanalyzer` | built-in binary-XML reader is used |
| reading decompiled code | `jadx` / `apktool` | triage still names the classes and literals |
| AES-CBC/CTR/ECB/CFB/OFB, RSA | `openssl` on PATH | install `pycryptodome` |
| AES-GCM | `pycryptodome` or `cryptography` | clear error telling you which |
| runtime key capture (last resort) | `frida` + `frida-tools`, device | the static, key-swap and client-patch routes need none of it |
| repacking a patched client | `apktool`, `zipalign`, `apksigner` | proxy-side key swap needs no repack |

Check the crypto side in one line: `python3 skills/decrypt-app-traffic/scripts/crypto-cli.py selftest`.

## Teaching it a new scheme

The skill is built to generalize: the analysis is driven by wire evidence and a parameter search, not
by a list of known apps. When a new case *does* need something added, there are only four places to
touch — keep target specifics out of all of them.

| What you learned | Where it goes |
|---|---|
| a new **cipher/mode/structure/layout** (a wrapping order, a header layout, a compression step) | `crypto-cli.py`: a `--structure` value or a post-processing step, plus a `selftest` case that round-trips it |
| a new **wire tell** (how to recognise the shape from a sample) | `ciphertext-analyze.py` hypotheses + a row in the shape catalogue in `references/recognize-scheme.md` |
| a new **artifact indicator** (an API, library, handshake marker, key-delivery pattern) | the `INDICATORS` table in `crypto-triage.py`, and a "what to do next" line if it changes the key route |
| a new **key-acquisition route** | the relevant reference (`static-key-hunt` / `key-exchange-mitm` / `patch-the-client` / `runtime-key-capture`) and, if it changes the priority order, the routing table in `SKILL.md` Step 4 |

Then record the case itself as a profile under `assets/examples/` — genericized (no real hosts, keys,
or client names). The profiles are the regression suite: each one should still emit a clean runbook
via `emit-reencrypt-config.py`, and each new scheme should be reachable by `crypto-cli.py solve`
without being told the answer.

## Status

- `reencrypt-config.json` is a **proposal** — the extension can't import it yet, so the runbook is the
  path that works today. The schema is deliberately 1:1 with `reencrypt.CapturePattern` /
  `reencrypt.Config` so the importer is a field copy.
- Instrumentation is deliberately the last rung: it is noisy, apps in this space detect it, and the
  device may not run it at all. Manipulating the key exchange in the proxy and patching the client
  cover the same ground, need no root, and keep working after any restart.
- Android is the better-covered platform for runtime work; iOS static analysis and the CommonCrypto
  hooks are covered, jailbreak-dependent steps are not automated.

Use only against applications you are authorized to test.
