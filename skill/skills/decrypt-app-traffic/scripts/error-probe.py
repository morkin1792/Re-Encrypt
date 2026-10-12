#!/usr/bin/env python3
"""
error-probe.py — make the crypto fail on purpose, and read the scheme off the error.

When you cannot tell the structure from the bytes and no candidate key works, stop guessing and ask
the implementation: send a *surgically* corrupted ciphertext and classify what comes back. Crypto
libraries are talkative — "Input length must be multiple of 16", "pad block corrupted",
"AEADBadTagException", "Wrong IV length" each pin down a different part of the scheme, and a client
stack trace usually names the class to open in jadx.

Two directions, and they are **not** equally safe:

  * `--response-mode` (SAFE, do this first): corrupt a captured *response* and let the **client** fail.
    Nothing reaches the server. This script writes the mutated bodies; you serve them with the proxy's
    match-and-replace / response interception, and read the error from logcat or the WebView console.
  * request probes (INTRUSIVE): corrupt a *request* and classify the **server's** answers. Malformed
    traffic lands in the target's logs and may trip monitoring, so it is opt-in, rate-limited, capped,
    and dry-run by default.

Usage
-----
  # 1) look at the mutations, send nothing (default)
  error-probe.py req.txt --field data --out probes/

  # 2) client-side oracle: variants to feed back to the app, plus how to read the error
  error-probe.py res.txt --response-mode --field data --out probes/

  # 3) server-side oracle: send through the proxy, rate-limited and capped
  error-probe.py req.txt --field data --send --proxy http://127.0.0.1:8080 \\
      --header 'X-Engagement: acme-2026' --delay 1.0 --max 10

  # HTTP/2-only edges (some CDNs drop HTTP/1.1): add --http2, or send probes/*.txt through the proxy
  # MCP instead (send_http2_request) and classify with:  error-probe.py --classify results.json

Each mutation is chosen to isolate one question; nothing here is a fuzzer. Read PROBES.md in --out for
the hypothesis behind every variant.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import time

BLOCK = 16


def die(msg, code=2):
    print("error-probe: %s" % msg, file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# raw HTTP message handling
# ---------------------------------------------------------------------------

def read_message(path):
    with open(path, "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition("\n\n")
        if not sep:
            die("%s has no header/body separator — save the raw message, headers included" % path)
    return head, body


def locate(body, head, args):
    """Return (value, rebuild) where rebuild(new_value) -> new body."""
    if args.whole_body:
        return body, (lambda v: v)
    if args.regex:
        rx = re.compile(args.regex, re.S)
        m = rx.search(body) or rx.search(head)
        if not m:
            die("--regex did not match")
        if not m.groups():
            die("--regex needs capturing group 1 = the ciphertext")
        target = m.group(1)
        return target, (lambda v, s=m.start(1), e=m.end(1): body[:s] + v + body[e:])
    if args.field:
        for rx in (r'"%s"\s*:\s*"([^"]*)"' % re.escape(args.field),      # JSON
                   r'(?:^|[?&])%s=([^&\s]*)' % re.escape(args.field),    # form / query
                   r'(?im)^%s:\s*(.*)$' % re.escape(args.field)):        # header
            m = re.search(rx, body) or re.search(rx, head)
            if m:
                src = body if (re.search(rx, body)) else head
                if src is head:
                    die("the field is in the headers — probe it with --regex against the header, or "
                        "move it into the body for this test")
                return m.group(1), (lambda v, s=m.start(1), e=m.end(1): body[:s] + v + body[e:])
        die("field %r not found in the body" % args.field)
    die("say where the ciphertext is: --field NAME, --regex 'RE with group 1', or --whole-body")


def fix_length(head, body):
    if re.search(r"(?im)^content-length:", head):
        head = re.sub(r"(?im)^content-length:.*$", "Content-Length: %d" % len(body.encode()), head)
    return head + "\r\n\r\n" + body


# ---------------------------------------------------------------------------
# the mutations — one question each
# ---------------------------------------------------------------------------

def decode_any(value):
    v = value.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", v):
        return "hex", binascii.unhexlify(v)
    b64u = bool(re.search(r"[-_]", v)) and not re.search(r"[+/]", v)
    try:
        fn = base64.urlsafe_b64decode if b64u else base64.b64decode
        return ("base64url" if b64u else "base64"), fn(v + "=" * (-len(v) % 4))
    except (binascii.Error, ValueError):
        return "raw", v.encode("latin-1", "replace")


def encode_any(raw, enc, pad=True):
    if enc == "hex":
        return raw.hex()
    if enc == "raw":
        return raw.decode("latin-1")
    out = (base64.urlsafe_b64encode if enc == "base64url" else base64.b64encode)(raw).decode()
    return out if pad else out.rstrip("=")


def flip(raw, index, bit=0x01):
    b = bytearray(raw)
    b[index] ^= bit
    return bytes(b)


def mutations(value):
    """[(name, mutated_value, question_it_answers)] — surgical, ~10 probes, never a fuzz run."""
    enc, raw = decode_any(value)
    out = []

    def add(name, newraw, why):
        out.append((name, encode_any(newraw, enc), why))

    if len(raw) >= BLOCK:
        add("flip-last-byte", flip(raw, len(raw) - 1),
            "Padding vs integrity: a padding error here (and only here) means CBC/ECB with PKCS#7 and "
            "NO MAC before decrypt. A tag error means AEAD — tampering needs the key. No error at all "
            "means a stream mode or NoPadding.")
        add("flip-first-byte", flip(raw, 0),
            "Is the head an IV? If only the FIRST plaintext block corrupts (or the server still "
            "accepts), the leading 16 bytes are the IV -> structure=iv_ct.")
        add("flip-middle-byte", flip(raw, len(raw) // 2),
            "Malleability: with CTR/CFB/OFB a single flipped ciphertext bit flips exactly one "
            "plaintext bit — targeted modification without the key (report it).")
    add("truncate-1", raw[:-1],
        "Block-size validation: 'Input length must be multiple of 16' names the cipher's block size "
        "and proves a padded block mode.")
    if len(raw) > 2 * BLOCK:
        add("truncate-block", raw[:-BLOCK],
            "Length still legal, content short: separates 'length rejected' from 'content rejected'.")
        add("swap-blocks", raw[:BLOCK] + raw[2 * BLOCK:3 * BLOCK] + raw[BLOCK:2 * BLOCK]
            + raw[3 * BLOCK:],
            "Block independence: if the plaintext comes back reordered, it is ECB. If only two blocks "
            "corrupt, CBC.")
    add("append-block", raw + bytes(range(BLOCK)),
        "Length stays a multiple of 16 -> isolates padding checks from length checks.")
    add("random-same-length", os.urandom(len(raw)) if raw else b"",
        "Equivalent to a wrong key: the baseline 'undecryptable but well-formed' error.")
    add("empty", b"", "Does the endpoint even require the field?")
    out.append(("invalid-encoding", value.strip()[:-2] + "!!" if len(value) > 2 else "!!",
                "Decode layer vs decrypt layer: a different error proves the outer encoding is "
                "validated before any crypto runs."))
    return enc, raw, out


# ---------------------------------------------------------------------------
# sending (request direction only, opt-in)
# ---------------------------------------------------------------------------

def send(raw_message, args):
    """Send one raw HTTP message with curl; return a fingerprint dict."""
    head, _, body = raw_message.partition("\r\n\r\n")
    lines = head.splitlines()
    m = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP", lines[0])
    if not m:
        die("first line is not a request line: %r" % lines[0][:80])
    method, path = m.group(1), m.group(2)
    host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), None)
    if not host:
        die("no Host header")
    scheme = "http" if args.plain_http else "https"
    url = "%s://%s%s" % (scheme, host, path)

    cmd = ["curl", "-sS", "-o", "-", "-w", "\\n__STATUS__%{http_code} __TIME__%{time_total}",
           "-X", method, url, "--max-time", str(args.timeout)]
    cmd += ["--http2"] if args.http2 else []
    cmd += ["-k"] if args.insecure else []
    if args.proxy:
        cmd += ["--proxy", args.proxy]
    for l in lines[1:]:
        if l.strip() and not l.lower().startswith(("content-length:", "host:")):
            cmd += ["-H", l.strip()]
    cmd += ["-H", "Host: %s" % host]
    for h in args.header or []:
        cmd += ["-H", h]
    if body:
        cmd += ["--data-binary", body]

    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout
    status = re.search(r"__STATUS__(\d+)", out)
    took = re.search(r"__TIME__([\d.]+)", out)
    payload = re.sub(r"\n?__STATUS__\d+ __TIME__[\d.]+$", "", out)
    return {
        "status": int(status.group(1)) if status else 0,
        "seconds": float(took.group(1)) if took else 0.0,
        "length": len(payload),
        "sha1": hashlib.sha1(payload.encode()).hexdigest()[:10],
        "excerpt": re.sub(r"\s+", " ", payload)[:200],
        "curl_error": p.stderr.strip()[:200],
    }


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
CLIENT_ERRORS = [
    (r"AEADBadTagException|MAC check failed|tag mismatch|InvalidCipherTextException",
     "AEAD (GCM/CCM) or encrypt-then-MAC: integrity IS checked. You cannot tamper without the key — "
     "get the key, don't fight the tag. Structure: iv_ct_tag / GCM."),
    (r"BadPaddingException|pad block corrupted|Invalid PKCS.?[57] padding|wrong final block length",
     "Padded block mode (CBC/ECB + PKCS#5/7) and NO integrity check before decrypt: the payload is "
     "malleable, and a distinguishable padding error is a padding oracle (report it)."),
    (r"Input length must be multiple of (\d+)|IllegalBlockSizeException",
     "Padded block cipher; the number in the message is the block size (16 = AES)."),
    (r"Wrong IV length: must be (\d+) bytes|InvalidAlgorithmParameterException",
     "The IV comes from the message and its length is validated — that pins ivLength and points at "
     "structure=iv_ct."),
    (r"Invalid AES key length: (\d+) bytes|InvalidKeyException",
     "The app told you the key length it expects."),
    (r"(AES|DES|RSA)/(CBC|ECB|CTR|GCM|CFB|OFB)/(\w+)",
     "The transform string leaked verbatim — that is the whole scheme."),
    (r"NoSuchAlgorithmException|NoSuchPaddingException",
     "Algorithm/padding name is in the message."),
    (r"JSONException|Unexpected token|JsonParseException|Expected BEGIN_OBJECT",
     "It DECRYPTED your corrupted bytes and only failed to parse them: no integrity at all, and a "
     "stream mode or NoPadding (ciphertext length == plaintext length)."),
    (r"at ([a-z][\w.]*\.[A-Z]\w+)\.", "Stack trace: that class is the crypto implementation — open it "
                                      "in jadx before doing anything else."),
]


def classify_client(text):
    hits = []
    for rx, meaning in CLIENT_ERRORS:
        m = re.search(rx, text)
        if m:
            hits.append({"matched": m.group(0)[:120], "means": meaning})
    return hits


def classify_server(results, baseline):
    """Group probes by response fingerprint and read the scheme off which classes exist."""
    conclusions = []
    groups = {}
    for name, r in results.items():
        key = (r["status"], r["sha1"])
        groups.setdefault(key, []).append(name)

    def same_as(a, b):
        return (results.get(a, {}).get("status"), results.get(a, {}).get("sha1")) == \
               (results.get(b, {}).get("status"), results.get(b, {}).get("sha1"))

    if baseline:
        ok = [n for n, r in results.items()
              if (r["status"], r["sha1"]) == (baseline["status"], baseline["sha1"])]
        if ok:
            conclusions.append("**%s produced the ORIGINAL response** — those bytes are not "
                               "authenticated, and whatever they cover is ignored or tolerated by the "
                               "server: %s" % (", ".join(ok), ", ".join(ok)))
    if len(groups) == 1:
        conclusions.append("Every probe got the same answer: the server rejects before it decrypts "
                           "(a length/MAC/schema check runs first), or it swallows all crypto errors "
                           "into one generic response. No oracle here — go back to getting the key.")
    else:
        listing = []
        for k, v in groups.items():
            sample = results[v[0]]["excerpt"][:60].strip()
            listing.append("**%s** `%s` ← %s" % (k[0], sample, ", ".join(v)))
        conclusions.append("%d distinguishable response class(es) → there IS an error oracle:\n  - %s"
                           % (len(groups), "\n  - ".join(listing)))
    if not same_as("truncate-1", "random-same-length"):
        conclusions.append("`truncate-1` differs from `random-same-length` → the ciphertext **length** "
                           "is validated separately: a padded block mode (block size is what the "
                           "length must be a multiple of).")
    pad_words = re.compile(r"(?i)pad|BadPadding|block corrupted")
    last, mid = results.get("flip-last-byte", {}), results.get("flip-middle-byte", {})
    if last and mid and not same_as("flip-last-byte", "flip-middle-byte") \
            and pad_words.search(last.get("excerpt", "")):
        conclusions.append("**Padding oracle.** Corrupting the last block gives a *padding* error while "
                           "corrupting the middle gives a different one — the padding check is "
                           "observable, so the payload can be decrypted (and forged) without the key. "
                           "That is a finding in its own right; see crypto-weaknesses.md. Exploiting it "
                           "fully takes ~256 requests per byte, so treat it as a scope decision, not a "
                           "default next step.")
    elif last and not same_as("flip-last-byte", "random-same-length"):
        conclusions.append("`flip-last-byte` is its own class → the last block is treated specially "
                           "(padding or a trailing MAC). Compare its body with the others before "
                           "concluding which.")
    if same_as("flip-middle-byte", "flip-last-byte") and not same_as("flip-middle-byte",
                                                                     "random-same-length"):
        conclusions.append("Middle and last flips behave alike → integrity covers the whole "
                           "ciphertext (MAC/AEAD), not just the padding.")
    if not same_as("invalid-encoding", "random-same-length"):
        conclusions.append("`invalid-encoding` is its own class → the outer encoding is decoded and "
                           "validated before any crypto; get that layer right first.")
    for name in ("truncate-1", "flip-last-byte", "random-same-length"):
        r = results.get(name) or {}
        hits = classify_client(r.get("excerpt", ""))
        for h in hits:
            conclusions.append("`%s` leaked a library error (%s): %s" % (name, h["matched"], h["means"]))
    return conclusions


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("message", nargs="?", help="raw HTTP request (or response, with --response-mode)")
    ap.add_argument("--field", help="JSON/form field holding the ciphertext")
    ap.add_argument("--regex", help="capture regex, group 1 = the ciphertext")
    ap.add_argument("--whole-body", action="store_true")
    ap.add_argument("--out", metavar="DIR", help="write the probe messages + PROBES.md here")
    ap.add_argument("--response-mode", action="store_true",
                    help="mutate a captured RESPONSE for the client to choke on (sends nothing)")
    ap.add_argument("--classify", metavar="FILE",
                    help="classify results collected elsewhere: {\"probe\": {status,sha1,excerpt}}")

    g = ap.add_argument_group("sending (request direction only — intrusive, opt in)")
    g.add_argument("--send", action="store_true", help="actually send the probes")
    g.add_argument("--proxy", help="send through this proxy so every probe is auditable")
    g.add_argument("--header", action="append", help="extra header, e.g. an engagement marker")
    g.add_argument("--delay", type=float, default=1.0, help="seconds between probes (default 1.0)")
    g.add_argument("--max", type=int, default=12, help="hard cap on requests (default 12)")
    g.add_argument("--timeout", type=float, default=20.0)
    g.add_argument("--http2", action="store_true", help="some edges drop HTTP/1.1")
    g.add_argument("--plain-http", action="store_true")
    g.add_argument("--insecure", action="store_true", help="curl -k (proxy MITM certs)")
    args = ap.parse_args()

    if args.classify:
        with open(args.classify) as fh:
            data = json.load(fh)
        baseline = data.pop("baseline", None)
        print("# Error-oracle classification\n")
        for c in classify_server(data, baseline):
            print("- %s" % c)
        return 0

    if not args.message:
        ap.error("give a raw HTTP message (or --classify FILE)")
    head, body = read_message(args.message)
    value, rebuild = locate(body, head, args)
    enc, raw, muts = mutations(value)
    print("ciphertext field: %d chars, %s → %d bytes (%s)"
          % (len(value), enc, len(raw), "block-aligned" if len(raw) % BLOCK == 0 else "not aligned"),
          file=sys.stderr)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
    lines = ["# Error probes for `%s`" % os.path.basename(args.message), "",
             "Field: %d chars, %s, %d bytes decoded.%s" % (len(value), enc, len(raw),
                                                           "" if len(raw) % BLOCK == 0 else
                                                           " Not a multiple of 16 — expect a stream mode."),
             ""]
    if args.response_mode:
        lines += ["**Client-side oracle (safe: nothing is sent to the server).** Serve each variant to "
                  "the app in place of the real response — Burp match-and-replace on the response body, "
                  "or response interception — and read the client's error:", "",
                  "```bash",
                  "adb logcat -c && adb logcat | grep -iE "
                  "'exception|crypt|cipher|pad|tag|iv |key|at [a-z][a-z0-9.]*\\.[A-Z]'",
                  "# WebView/hybrid app: chrome://inspect → Console (the exception often has the file "
                  "and function too)",
                  "```", "",
                  "Then paste the error text into: `error-probe.py --classify` is for server results; "
                  "for a client error just match it against the table in "
                  "`references/error-oracles.md` (it maps each exception to a scheme fact).", ""]
    else:
        lines += ["**Server-side oracle (intrusive).** Each probe is one request. Send them through the "
                  "proxy so they are auditable, one at a time, and stop as soon as a class is "
                  "distinguishable — you do not need the whole set.", ""]
    lines += ["| Probe | What it answers |", "|---|---|"]
    for name, _v, why in muts:
        lines.append("| `%s` | %s |" % (name, why.replace("\n", " ")))
    lines += ["", "Original value (for reference): `%s…`" % value[:60], ""]

    messages = {}
    for name, newvalue, _why in muts:
        newbody = rebuild(newvalue)
        messages[name] = fix_length(head, newbody)
        if args.out:
            with open(os.path.join(args.out, "probe-%s.txt" % name), "w") as fh:
                fh.write(messages[name])

    if args.out:
        with open(os.path.join(args.out, "PROBES.md"), "w") as fh:
            fh.write("\n".join(lines))
        print("wrote %d probe messages + PROBES.md to %s" % (len(messages), args.out), file=sys.stderr)
    else:
        print("\n".join(lines))

    if args.response_mode:
        print("\nResponse variants written. Nothing was sent — serve them to the client and read the "
              "error (see PROBES.md).", file=sys.stderr)
        return 0
    if not args.send:
        print("\nDry run: nothing sent. Review the probes, then add --send --proxy <url> "
              "(rate-limited, capped at --max) or send probes/*.txt through the proxy MCP and classify "
              "with --classify.", file=sys.stderr)
        return 0

    if args.proxy is None:
        die("--send needs --proxy <url> so every malformed request is auditable in the proxy history. "
            "If you truly cannot proxy, pass --proxy '' deliberately.", 2)
    if args.proxy == "":
        print("WARNING: sending probes DIRECTLY (no proxy) — nothing will be recorded in history",
              file=sys.stderr)
    order = ["random-same-length", "truncate-1", "flip-last-byte", "flip-middle-byte",
             "flip-first-byte", "invalid-encoding", "append-block", "truncate-block", "swap-blocks",
             "empty"]
    todo = [n for n in order if n in messages][: args.max]
    print("sending %d probe(s) %s, %.1fs apart"
          % (len(todo), "through " + args.proxy if args.proxy else "directly", args.delay),
          file=sys.stderr)
    results = {}
    baseline = None
    original = fix_length(head, body)
    baseline = send(original, args)
    print("  %-20s %s %sB %s" % ("baseline(original)", baseline["status"], baseline["length"],
                                 baseline["sha1"]), file=sys.stderr)
    for name in todo:
        time.sleep(args.delay)
        r = send(messages[name], args)
        results[name] = r
        print("  %-20s %s %sB %s  %s" % (name, r["status"], r["length"], r["sha1"],
                                         r["excerpt"][:60]), file=sys.stderr)

    print("\n# Error-oracle classification\n")
    for c in classify_server(results, baseline):
        print("- %s" % c)
    if args.out:
        with open(os.path.join(args.out, "results.json"), "w") as fh:
            json.dump(dict(results, baseline=baseline), fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
