# Same profile, no Burp extension

The profile and `crypto-cli.py` are the portable part. Use them anywhere.

## One-off decrypt / encrypt

```bash
# read a captured value
python3 "$SKILL"/scripts/crypto-cli.py dec --mode CBC --structure iv_ct --key file:hex:keys/aes.key --in-file ct.txt

# craft a payload to send by hand
printf '%s' '{"amount":1,"to":"attacker"}' \
  | python3 "$SKILL"/scripts/crypto-cli.py enc --mode CBC --structure iv_ct --key file:hex:keys/aes.key
```

Bulk-decrypt a saved session (each line one ciphertext):

```bash
while read -r ct; do python3 "$SKILL"/scripts/crypto-cli.py dec … --data "$ct"; echo; done < cts.txt
```

## mitmproxy addon

Transparent decrypt/re-encrypt for the whole session — the equivalent of Re:Encrypt's *patch proxy*:

```python
# crypto_addon.py —  mitmproxy -s crypto_addon.py
import json, subprocess
from mitmproxy import http

CLI = ["python3", "/abs/path/crypto-cli.py"]
OPTS = ["--mode", "CBC", "--structure", "iv_ct", "--key", "file:hex:/tmp/aes.key"]
FIELD = "data"          # the JSON param carrying the ciphertext
HOSTS = ("api.target.example.com",)

def _run(verb, payload: str) -> str:
    p = subprocess.run(CLI + [verb] + OPTS + ["--data", payload], capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode())
    return p.stdout.decode()

def request(flow: http.HTTPFlow):
    if flow.request.host not in HOSTS or not flow.request.content:
        return
    body = json.loads(flow.request.get_text())
    if FIELD in body:
        # decrypt for visibility, edit here if you want, then re-encrypt
        plain = _run("dec", body[FIELD])
        flow.metadata["plaintext"] = plain          # visible in the flow details
        body[FIELD] = _run("enc", plain)
        flow.request.set_text(json.dumps(body))

def response(flow: http.HTTPFlow):
    if flow.request.host not in HOSTS or not flow.response.content:
        return
    try:
        body = json.loads(flow.response.get_text())
    except ValueError:
        return
    if FIELD in body:
        body[FIELD] = json.loads(_run("dec", body[FIELD]))
        flow.response.set_text(json.dumps(body))    # readable in the UI and in any downstream tool
```

Recompute a body signature in the same `request()` hook, after re-encryption — that is the natural
place for it (`integrity-and-signatures.md`).

## Burp without Re:Encrypt — Python Scripter / an extension

If Re:Encrypt isn't loaded, Burp's **Python Scripter** (Jython, so python 2.7) can do the same job in
~30 lines: on a Repeater/Intruder request, take the body, shell out to the worker, and rebuild the
message. The parts people get wrong:

- Filter on the tool (`toolFlag == callbacks.TOOL_REPEATER or ... TOOL_INTRUDER`) and on
  `messageIsRequest`, or you will transform responses and re-transform your own output.
- Rebuild with `helpers.buildHttpMessage(headers, body)` — it fixes `Content-Length` for you; hand-built
  bodies with a stale length get rejected and look like a crypto failure.
- Pass the payload to the worker as **base64 on argv** (or via a temp file) so quoting and binary don't
  corrupt it, and read the result from stdout only.
- Keep the wrapper shape in one place (`{"data": <blob>}` vs a bare body) — that is the part that
  differs per app.

```python
enc = subprocess.check_output([NODE, SCRIPT, b64encode(json.dumps(body_json))])
new_body = array.array('B', json.dumps({"request": enc}))
messageInfo.setRequest(helpers.buildHttpMessage(headers, new_body))
```

The same pattern works from a Montoya extension in Java, and from `mitmproxy` above. Whatever the
host, keep the crypto in one worker script (`crypto-cli.py`, or the app's own library via
`$SKILL/scripts/oracle/js-crypto-oracle.js`) rather than in the proxy glue.

## Caido / other proxies

Any proxy with a scripting hook works the same way: on request, extract the field, shell out to
`crypto-cli.py dec`, expose the plaintext, and encrypt again before forwarding. Keep the crypto in the
CLI rather than reimplementing it in the proxy's language — one place to fix when a parameter turns
out to be wrong.

## CyberChef / manual sharing

For a screenshot or to hand a recipe to someone without the toolkit: `From Base64` → `AES Decrypt`
with the key/IV and mode from the profile. Match the profile's structure by splitting the IV manually
(first 16 bytes) when the layout is `iv_ct`. Useful for evidence, not for a working loop.

## Keep the profile as the source of truth

Whichever front end you use, the profile (`assets/crypto-profile.schema.json`) is what you update when
a parameter changes, and `emit-reencrypt-config.py` regenerates the runbook and the config from it.
That way a rotated key or a corrected mode is a one-line edit, not a hunt through three tools.
