# Configuring Re:Encrypt from a crypto profile

Re:Encrypt captures a span of a request/response with a regex and runs either a **built-in engine**
(AES / RSA) or a **custom command** over it — decrypt for display, encrypt on send. This maps the
profile onto its fields. `emit-reencrypt-config.py` generates exactly these values as a runbook.

## 1. The capture pattern

In **Capturing + Processing**, one pattern per encrypted field, per direction (request/response).

| Profile `location.type` | "What will be captured" | Generated regex |
|---|---|---|
| `header` | Header | `(?i)<name>: (.*)` |
| `url_param` | Parameter (URL-encoded) | `<name>=(.*?)(?:&\|$)` |
| `json_param` | Parameter (JSON) | `"<name>":"(.*?)"` |
| `whole_body` | Whole Body | `(?s)(?<=\r\n\r\n)(.+)` |
| `custom_regex` | Custom Regex | yours |

**Capturing group 1 must be exactly the ciphertext span** — that span is what gets replaced on
re-encrypt. This is the single most common configuration mistake: a regex that captures the quotes,
the `data=` prefix or a trailing `&` will decrypt to garbage and corrupt the request on send. Write a
custom regex when the value is nested (e.g. a JSON param inside a JSON string) and test it against a
saved sample first.

Targeting: leave the URL regex empty to match everything, set `urlTargetRegex` to scope it to the
app's API, or tick *use project scope* to follow Burp's scope. Scope it — analytics SDKs and CDN
traffic will otherwise be run through your crypto and fill the log with failures.

## 2. Engine mode (AES / RSA)

Encryption Mode → **AES** or **RSA** and fill the panel. The parameters, as they are stored (this is
what the emitted `reencrypt-config.json` contains):

**AES**

| Param | Values | Notes |
|---|---|---|
| `mode` | `CBC` `ECB` `CTR` `GCM` `CFB` `OFB` | |
| `ciphertextStructure` | `raw` `iv_ct` `iv_ct_tag` `openssl` `jwe` | how IV/tag/salt are packed |
| `padding` | `PKCS5Padding` `NoPadding` `ISO10126Padding` | CBC/ECB only |
| `encoding` | `Base64` `Base64URL` `Hex` `Raw` | outer, on the wire |
| `mirrorEncoding` | `true` / `false` | `false` → set `inputEncoding` + `outputEncoding` separately |
| `ivLength` | bytes (default 16, GCM 12) | `iv_ct` / `iv_ct_tag` |
| `gcmTagLength` | bits, default `128` | |
| `keyDerivation` | `evp_md5` `evp_sha256` `pbkdf2` | `openssl` structure only |
| `pbkdf2Iterations`, `opensslKeyLength` | ints | `openssl` structure |
| `key`, `iv` | value / path / command | + `…Format`, `…Source`, `…ReloadFile` (below) |

**RSA**

| Param | Values |
|---|---|
| `encryptionScheme` | `PKCS1` (RSAES-PKCS1-v1_5) · `OAEP` · `Raw` (no padding) |
| `oaepDigest` | `SHA-1` `SHA-256` … (OAEP only) |
| `publicKey`, `privateKey` | PEM text, file path, or command · `…Source`, `…FileFormat` (`PEM`/`DER`), `…ReloadFile` |

## 3. Key material sources — pick by whether the key moves

| `…Source` | Behaviour | Use when |
|---|---|---|
| `text` | literal, stored in the config | the key is static (hardcoded/derived once) |
| `file` | file read per operation when `…ReloadFile=true` | **the key rotates** — point it at the one-line file your capture keeps current (a proxy-side handshake patcher, a patched client, or `frida-run.py --key-file`) |
| `command` | shell command run per operation; `{DATA}`/`{FILE}` available | the key must be fetched or computed per request (`adb shell cat …`, a derivation script) |

`…Format` (`Hex` / `Base64` / `UTF-8`) says how to turn that text into bytes. A 32-character key is
`UTF-8` (32 bytes) more often than `Base64` (24 bytes) or `Hex` (16 bytes) — getting this wrong is
indistinguishable from a wrong key, so try the alternatives when a decrypt fails.

**Session keys: in-proxy you get "the newest key", not "the right key."** A key file or key command
only ever sees the payload being processed — never the request headers — so it cannot choose a key by
session id. Keep one device/session live at a time and have your capture keep that file current. For
older captures, or two sessions in one history, decrypt offline where the session *is* known:

```bash
crypto-cli.py keys --key-log ./key --session <sid>                       # every key that session had
crypto-cli.py dec … --key-log ./key --session <sid> --in-file body.json
```

## 4. Custom command mode

Encryption Mode → **Custom Command** and give a decrypt/encrypt pair. Contract:

- `{DATA}` is substituted inline; **`{FILE}` is a temp file holding the captured data — prefer it**
  (no quoting/binary/length problems).
- stdout is the result; **exactly one trailing newline is stripped**, everything else preserved.
- non-zero exit = failure (the message is surfaced, and the cached value is used if caching is on).
- stderr is merged into the output stream — keep diagnostics out of stdout in a working command.

`crypto-cli.py` is written to this contract — note `--quiet`: without it, its diagnostics would be
merged into the plaintext by the rule above.

```bash
# Decrypt Command
python3 /abs/path/crypto-cli.py dec --mode CBC --structure iv_ct --key file:hex:/tmp/aes.key --quiet --in-file {FILE}
# Encrypt Command
python3 /abs/path/crypto-cli.py enc --mode CBC --structure iv_ct --key file:hex:/tmp/aes.key --quiet --in-file {FILE}
```

Use custom commands whenever the scheme has a step the engines don't model (an extra wrapping layer,
a body signature to recompute, a bespoke KDF, chunking rules) — one wrapper script keeps everything
in one place and works outside Burp too.

## 5. Where you see the result

- **Repeater / Proxy** — the extension's editor tab shows the plaintext; edit there and Send
  re-encrypts. This is the normal working loop.
- **Patch proxy** (per pattern) — decrypts and re-encrypts in flight, so history and every other tool
  see plaintext. This is what makes a key swap work without an extension: after you substitute your
  public key in the exchange, one patched direction keeps the app running while you read it.

  | Direction | `privateKey` | `publicKey` | Why |
  |---|---|---|---|
  | responses the server encrypts to the *client's* key (you swapped it) | **yours** | the app's **original** | you decrypt, the app still can |
  | requests the client encrypts to the *server's* key (you swapped it) | **yours** | the **server's real** key | you decrypt, the server still can |

  Keep the original key the first time you see it — the outbound leg is impossible without it. Verify
  with an unmodified message before editing anything: same response as with the proxy off.

  **Auto-load reads `enabled`; the import dialog does not.** In a watched file, a pattern with
  `"enabled": false` stays parked and one without the field is live — so a producer can hold entries
  ready without arming them. A file opened through *Import* ignores the field: the dialog's checkbox
  decides, and export never writes it.

  **Tampering in flight: mutate in the ENCRYPT command, never in the decrypt one.** Patch proxy runs
  decrypt, then feeds that output straight to encrypt, so a hook that rewrites a field on decrypt does
  change what goes on the wire — and also rewrites every later *view* of that message, because the
  decrypt command runs again whenever anything displays or logs it. Burp's stored *original* then
  decrypts to the tampered value too, the before/after in the proxy history become identical, and the
  log records your value as if the server had sent it. Put the rewrite after decryption instead:

  | Command | Job |
  |---|---|
  | decrypt | **observe only** — return the plaintext untouched (stash it, log it, whatever you need) |
  | encrypt | **mutate** — apply the change, then encrypt |

  Same result on the wire, but the original stays readable as the server sent it, which is what the
  evidence for a finding depends on.
- **Log file** (`~/reencrypt.log` by default) — every decrypt, for grepping the whole session later.
- **Cache** — a ciphertext→plaintext store used when a decrypt command fails, so a momentarily-stale
  key doesn't blank the view; the message is annotated when a cached value is served. Garbage
  detection keeps wrong-key output out of the cache. If you see "cached" annotations, the live key or
  command is failing — fix that rather than trusting the view.
- **Intruder** — either *auto-encrypt intruder requests* (define the attack in plaintext; matched
  spans are encrypted per request) or the *payload processor* rule (each payload encrypted
  individually). Auto-encrypt is what you want for a body that is encrypted as a whole.

## 6. Troubleshooting, by symptom

| Symptom | Likely cause | Fix |
|---|---|---|
| Nothing appears in the tab | regex doesn't match, or URL targeting excludes the host | test the regex against a saved raw message; widen targeting |
| Plaintext with junk at the edges | group 1 includes quotes/prefix/`&` | tighten the capture to the value only |
| First 16 bytes garbage, rest fine | wrong IV (CBC) | check `structure`/`ivLength`, or the fixed-IV assumption |
| All garbage | wrong key, wrong key *format*, or wrong structure | try `Hex`/`UTF-8`/`Base64` key format; re-check structure arithmetic |
| Worked, then stopped | key rotated (renewal mid-session) | switch the key to `file`/`command` source with reload on; check the key log for a newer key |
| Plaintext ends up with `crypto-cli: …` text in it | stderr is merged into command output | add `--quiet` to both commands |
| Handshake replayed from Repeater yields no key | a proxy-side patcher filters on `ToolType.PROXY` | mint keys by driving the app through the proxy, or run the handshake from a script |
| Server rejects edited requests only | body signature/nonce | see `integrity-and-signatures.md` |
| Server rejects *unmodified* round-trips | encrypt side differs from the app (padding, IV placement, encoding, RSA scheme) | fix encrypt first; test with `crypto-cli.py enc` then `dec` |
| JWE re-encrypt fails | no captured header/wrapped key yet | decrypt a real token first (engine remembers them for the session) |

## 7. The import file

`reencrypt-config.json` (schema: `assets/reencrypt-config.schema.json`) holds all of the above in one
file. The extension does not read it yet — today it is the record of the decision and the input for
the runbook; every key maps 1:1 onto `reencrypt.CapturePattern` / `reencrypt.Config`, so keep it
accurate and the future import is a straight field copy.
