#!/usr/bin/env python3
"""
ciphertext-analyze.py — find the encrypted part of a request and rank what the scheme could be.

Feed it whatever you have: a bare value, raw HTTP requests/responses saved from the proxy, a HAR
export, or a directory of those. It locates the high-entropy fields, then for each candidate reports
the outer encoding, the structure (JWE / OpenSSL `Salted__` / IV+CT / IV+CT+tag / RSA block / …), the
implied cipher family, and the exact next command to try — plus the Re:Encrypt capture pattern that
would target that field.

Usage:
  ciphertext-analyze.py --value "U2FsdGVkX1..."            # one value
  ciphertext-analyze.py req1.txt req2.txt req3.txt         # raw HTTP messages (cross-sample analysis)
  ciphertext-analyze.py export.har --host api.example.com  # HAR, filtered to one host
  ciphertext-analyze.py samples/ --json                    # machine-readable

With two or more samples it also reports what varies *between* them — constant prefixes (static IV,
key id, version byte), whether lengths are block-aligned, and whether identical plaintexts produce
identical ciphertexts (deterministic encryption — a finding in its own right).

Give it samples of the SAME endpoint when you can: cross-sample structure is the strongest signal.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
import re
import sys
import urllib.parse
from collections import Counter

BLOCK = 16
MIN_LEN = 16


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def shannon(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 0x20 <= x < 0x7F or x in (9, 10, 13))
    return ok / len(b)


def try_decode(s: str):
    """Return (encoding, raw_bytes) for the most plausible outer encoding."""
    enc, raw = _try_decode(s)
    if enc == "raw" and " " in s:
        # a form-encoded '+' arrives here as a space; put it back before giving up
        enc2, raw2 = _try_decode(s.replace(" ", "+"))
        if enc2 != "raw":
            return enc2, raw2
    return enc, raw


def _try_decode(s: str):
    t = s.strip().strip('"')
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t) and len(t) >= 2 * MIN_LEN:
        return "hex", binascii.unhexlify(t)
    b64u = bool(re.search(r"[-_]", t)) and not re.search(r"[+/]", t)
    alphabet = r"A-Za-z0-9_\-" if b64u else r"A-Za-z0-9+/"
    if re.fullmatch(r"[%s]+={0,2}" % alphabet, t) and len(t) >= MIN_LEN:
        try:
            fn = base64.urlsafe_b64decode if b64u else base64.b64decode
            raw = fn(t + "=" * (-len(t) % 4))
            if raw:
                return ("base64url" if b64u else "base64"), raw
        except (binascii.Error, ValueError):
            pass
    return "raw", t.encode("latin-1", "replace")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# candidate extraction from HTTP / HAR / plain files
# ---------------------------------------------------------------------------
NAME_HINT = re.compile(r"(?i)\b(?:data|payload|enc(?:rypted)?|cipher|ct|body|blob|content|msg|message|"
                       r"request|req|params?|value|token|d|p|q|jwe|secure)\b")
SIG_NAME = re.compile(r"(?i)(?:signature|sign|sig|hmac|mac|digest|checksum|hash|integrity|nonce|"
                      r"timestamp|\bts\b|salt)")
DIGEST_LEN = {16: "MD5 / AES block", 20: "SHA-1", 28: "SHA-224", 32: "SHA-256 / HMAC-SHA256",
              48: "SHA-384", 64: "SHA-512"}
BORING_HEADERS = {"host", "user-agent", "accept", "accept-encoding", "accept-language", "connection",
                  "content-length", "content-type", "cache-control", "pragma", "date", "server",
                  "referer", "origin", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest"}


class Candidate:
    def __init__(self, value, where, kind, name=None, message=None):
        self.value = value
        self.where = where          # human description
        self.kind = kind            # header | url_param | json_param | form_param | body | cookie | value
        self.name = name
        self.message = message      # request identity, for grouping

    def key(self):
        return (self.kind, self.name, self.where)


def candidates_from_http(text: str, label: str):
    """Parse a raw HTTP message (request or response) and yield candidates."""
    out = []
    head, _, body = text.partition("\r\n\r\n")
    if not _:
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return out
    start = lines[0]
    ident = label
    m = re.match(r"([A-Z]+) (\S+) HTTP/", start)
    if m:
        ident = "%s %s" % (m.group(1), m.group(2).split("?")[0])
        for k, v in urllib.parse.parse_qsl(urllib.parse.urlparse(m.group(2)).query):
            out.append(Candidate(v, "URL param `%s` of %s" % (k, ident), "url_param", k, ident))
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() in BORING_HEADERS:
            continue
        if k.lower() == "cookie":
            for ck, cv in [p.split("=", 1) for p in v.split(";") if "=" in p]:
                out.append(Candidate(cv.strip(), "cookie `%s` of %s" % (ck.strip(), ident), "cookie",
                                     ck.strip(), ident))
            continue
        v = re.sub(r"(?i)\A(?:Bearer|Basic|Token|JWT)\s+", "", v)   # the scheme is not ciphertext
        out.append(Candidate(v, "header `%s` of %s" % (k, ident), "header", k, ident))
    out.extend(candidates_from_body(body, ident))
    return out


def candidates_from_body(body: str, ident: str):
    out = []
    body = body.strip()
    if not body:
        return out
    if body[:1] in "{[":
        try:
            out.extend(_walk_json(json.loads(body), ident))
            return out
        except ValueError:
            pass
    if "=" in body and "&" in body or re.fullmatch(r"[^=&\s]+=[^&]*", body or " "):
        pairs = urllib.parse.parse_qsl(body)
        if pairs:
            for k, v in pairs:
                out.append(Candidate(v, "form param `%s` of %s" % (k, ident), "form_param", k, ident))
            return out
    out.append(Candidate(body, "whole body of %s" % ident, "body", None, ident))
    return out


def _walk_json(obj, ident, path="$"):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_json(v, ident, "%s.%s" % (path, k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            out.extend(_walk_json(v, ident, "%s[%d]" % (path, i)))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        name = path.split(".")[-1].split("[")[0]
        out.append(Candidate(str(obj), "JSON param `%s` (%s) of %s" % (name, path, ident), "json_param",
                             name, ident))
    return out


def candidates_from_har(text: str, host_filter=None):
    out = []
    har = json.loads(text)
    for e in har.get("log", {}).get("entries", []):
        req = e.get("request", {})
        url = req.get("url", "")
        if host_filter and host_filter not in url:
            continue
        ident = "%s %s" % (req.get("method", "?"), urllib.parse.urlparse(url).path or "/")
        for q in req.get("queryString", []) or []:
            out.append(Candidate(q.get("value", ""), "URL param `%s` of %s" % (q.get("name"), ident),
                                 "url_param", q.get("name"), ident))
        for h in req.get("headers", []) or []:
            if (h.get("name", "").lower()) not in BORING_HEADERS:
                out.append(Candidate(h.get("value", ""), "header `%s` of %s" % (h.get("name"), ident),
                                     "header", h.get("name"), ident))
        pd = (req.get("postData") or {}).get("text")
        if pd:
            out.extend(candidates_from_body(pd, ident))
        content = ((e.get("response") or {}).get("content") or {}).get("text")
        if content:
            out.extend(candidates_from_body(content, "response of " + ident))
    return out


def score_candidate(c: Candidate) -> float:
    v = c.value.strip()
    if len(v) < MIN_LEN:
        return 0.0
    enc, raw = try_decode(v)
    s = 0.0
    if enc != "raw":
        s += 25
    s += min(len(raw), 512) / 512 * 20
    ent = shannon(raw)
    s += max(0.0, (ent - 4.0)) / 4.0 * 40
    if printable_ratio(raw) > 0.95 and enc != "raw":
        s -= 25                                      # decodes to text: encoding, not encryption
    if c.name and NAME_HINT.search(c.name):
        s += 15
    if v.count(".") == 4:
        s += 30                                      # JWE compact
    if raw[:8] == b"Salted__":
        s += 40
    if c.kind in ("body", "json_param", "form_param"):
        s += 5
    return s


# ---------------------------------------------------------------------------
# per-value analysis
# ---------------------------------------------------------------------------

def analyze_value(value: str) -> dict:
    v = value.strip().strip('"')
    if "%" in v and re.search(r"%[0-9a-fA-F]{2}", v):
        unq = urllib.parse.unquote_plus(v)
        if unq != v:
            v = unq
    enc, raw = try_decode(v)
    a = {
        "value_preview": v[:120] + ("…" if len(v) > 120 else ""),
        "wire_length": len(v),
        "outer_encoding": enc,
        "decoded_length": len(raw),
        "entropy": round(shannon(raw), 2),
        "printable_ratio": round(printable_ratio(raw), 2),
        "block_aligned": len(raw) % BLOCK == 0,
        "hypotheses": [],
        "observations": [],
    }
    H = a["hypotheses"]
    O = a["observations"]

    segs = v.split(".")
    # ---- JOSE ----
    if len(segs) == 5:
        hdr = _jose_header(segs[0])
        sizes = [len(b64u_dec(s)) if s else 0 for s in segs]
        a["jose_segments"] = sizes
        a["decoded_length"] = sizes[3]
        a["block_aligned"] = sizes[3] % BLOCK == 0
        O.append("segment sizes (bytes): header %d · wrapped key %d · IV %d · ciphertext %d · tag %d"
                 % tuple(sizes))
        if sizes[2] in (12, 16) and sizes[4] in (0, 16):
            O.append("IV %d bytes / tag %d bytes — consistent with %s content encryption"
                     % (sizes[2], sizes[4], "AEAD (GCM)" if sizes[4] == 16 else "a non-AEAD mode (CTR/CBC)"))
        alg, cenc = (hdr or {}).get("alg"), (hdr or {}).get("enc")
        mode = _enc_to_mode(cenc)
        wrapped_empty = not segs[1].strip()
        if wrapped_empty:
            key_note = ("**the wrapped-key segment is EMPTY** — the content key is not transported at "
                        "all: it was agreed in a separate key exchange (a handshake endpoint, or a key "
                        "delivered inside an earlier response). Find that exchange — that is where the "
                        "key is, and swapping the client's public key there hands it to you")
            cli = ("crypto-cli.py dec --structure jwe --key-log ./key --session <sid> --data '<token>' "
                   "   # once the exchange gives you keys")
        else:
            key_note = ("the key is the CEK in segment 2, wrapped with %s — unwrap it by swapping the "
                        "app's RSA public key for yours, or read the CEK where the app sets it"
                        % (alg or "an unknown alg"))
            cli = ("crypto-cli.py dec --structure jwe --priv file:yours.pem --jwe-state /tmp/jwe.json "
                   "--data '<token>'")
        H.append({
            "name": "JWE compact serialization%s" % (" (non-standard: empty wrapped key)" if wrapped_empty else ""),
            "confidence": 95 if hdr else 70,
            "detail": "5 base64url segments%s" % (" · alg=%s enc=%s" % (alg, cenc) if hdr else ""),
            "reencrypt": {"engine": "aes", "ciphertextStructure": "jwe", "mode": mode or "GCM",
                          "encoding": ("Base64" if re.search(r"[+/=]", segs[2] + segs[3])
                                       else "Base64URL")},
            "key_note": key_note,
            "cli": cli,
        })
        if not segs[4].strip():
            O.append("**the tag segment is empty/blank → no authentication tag**: the payload is "
                     "encrypted but not authenticated, so the server accepts any modification you make "
                     "(and this is a finding). `alg` in the header is then decorative — don't trust it "
                     "to tell you how the key is delivered.")
        if wrapped_empty and alg and alg.upper().startswith("RSA"):
            O.append("header claims alg=%s but nothing is wrapped — the header is cosmetic. Trust the "
                     "segment arithmetic and the handshake, not the header." % alg)
        if hdr:
            O.append("JWE protected header: %s" % json.dumps(hdr))
            if cenc and not _enc_to_mode(cenc):
                O.append("enc=%r is not a standard JOSE value — a custom build; treat the mode as "
                         "unconfirmed" % cenc)
    elif len(segs) == 3 and _jose_header(segs[0]):
        hdr = _jose_header(segs[0])
        body = None
        try:
            body = json.loads(b64u_dec(segs[1]))
        except Exception:
            pass
        H.append({
            "name": "JWS/JWT — signed, NOT encrypted",
            "confidence": 95,
            "detail": "header %s; payload is readable base64url" % json.dumps(hdr),
            "reencrypt": None,
            "key_note": "nothing to decrypt. If you need to *modify* it you need the signing key "
                        "(HS* → try weak/leaked secrets; RS*/ES* → you cannot forge without the private key)",
            "cli": None,
        })
        if body:
            O.append("JWT claims: %s" % json.dumps(body)[:300])

    # ---- OpenSSL enc ----
    if raw[:8] == b"Salted__":
        H.append({
            "name": "OpenSSL `enc` format (Salted__ + 8-byte salt + ciphertext)",
            "confidence": 95,
            "detail": "salt=%s, ciphertext=%d bytes" % (raw[8:16].hex(), len(raw) - 16),
            "reencrypt": {"engine": "aes", "ciphertextStructure": "openssl", "mode": "CBC",
                          "keyDerivation": "evp_md5", "encoding": _ui_enc(enc)},
            "key_note": "the app holds a *password*, not a key: key+IV are derived per message from the "
                        "salt (EVP_BytesToKey MD5 by default, PBKDF2 on newer openssl). This is also "
                        "exactly what `CryptoJS.AES.encrypt(data, \"string\")` emits — and then the key is "
                        "AES-256 no matter how short the literal is, so hunt for any string literal, not "
                        "for a 16/32-byte one",
            "cli": "crypto-cli.py dec --structure openssl --mode CBC --kdf evp-md5 --key utf8:<password> --data '<ct>'",
        })

    # ---- gzip / protobuf / plain text mistaken for crypto ----
    if raw[:2] == b"\x1f\x8b":
        O.append("gzip magic — this is compressed, not encrypted (gunzip it)")
    if a["printable_ratio"] > 0.95 and enc != "raw" and len(raw) > 8:
        O.append("decodes to printable text (%s) — this field is *encoded*, not encrypted: %r"
                 % (enc, raw[:80].decode("utf-8", "replace")))
    if a["entropy"] < 6.0 and len(raw) >= 64 and a["printable_ratio"] < 0.95:
        O.append("entropy %.2f bits/byte is low for ciphertext (%d bytes) — could be protobuf, a "
                 "serialized object, or a partially-encoded structure" % (a["entropy"], len(raw)))

    # ---- symmetric structures ----
    if len(segs) != 5 and raw[:8] != b"Salted__" and len(raw) >= 16:
        dup = _ecb_repeats(raw)
        if a["block_aligned"]:
            H.append({
                "name": "block cipher, ciphertext only (structure=raw)",
                "confidence": 60,
                "detail": "%d bytes, multiple of 16 — CBC or ECB with padding; IV (if any) is not in "
                          "this field" % len(raw),
                "reencrypt": {"engine": "aes", "ciphertextStructure": "raw", "mode": "CBC",
                              "encoding": _ui_enc(enc), "padding": "PKCS5Padding"},
                "key_note": "look for a hardcoded/derived key, and for a fixed IV (often all-zero, the "
                            "key itself, or the first 16 bytes of the key)",
                "cli": "crypto-cli.py dec --structure raw --mode CBC --key hex:<key> --iv hex:<iv> --data '<ct>'",
            })
            if dup:
                H.append({
                    "name": "AES-ECB (or CBC with a fixed IV)",
                    "confidence": 85,
                    "detail": "%d repeated 16-byte block(s) — identical plaintext blocks map to "
                              "identical ciphertext blocks" % dup,
                    "reencrypt": {"engine": "aes", "ciphertextStructure": "raw", "mode": "ECB",
                                  "encoding": _ui_enc(enc), "padding": "PKCS5Padding"},
                    "key_note": "ECB needs no IV — the key alone decrypts it",
                    "cli": "crypto-cli.py dec --structure raw --mode ECB --key hex:<key> --data '<ct>'",
                })
                O.append("**Report-worthy on its own:** repeated blocks prove ECB/fixed-IV usage.")
        if (len(raw) - 16) % BLOCK == 0 and len(raw) > 16:
            H.append({
                "name": "IV prepended to the ciphertext (structure=iv_ct)",
                "confidence": 75,
                "detail": "16-byte IV + %d bytes of block-aligned ciphertext" % (len(raw) - 16),
                "reencrypt": {"engine": "aes", "ciphertextStructure": "iv_ct", "mode": "CBC",
                              "ivLength": "16", "encoding": _ui_enc(enc), "padding": "PKCS5Padding"},
                "key_note": "only the key is missing — the IV travels with each message",
                "cli": "crypto-cli.py dec --structure iv_ct --mode CBC --key hex:<key> --data '<ct>'",
            })
        if not a["block_aligned"]:
            H.append({
                "name": "stream-ish mode (CTR / GCM / CFB / OFB)",
                "confidence": 70,
                "detail": "%d bytes, not a multiple of 16 — no block padding, so the ciphertext length "
                          "equals the plaintext length (+ any IV/tag)" % len(raw),
                "reencrypt": {"engine": "aes", "ciphertextStructure": "iv_ct", "mode": "CTR",
                              "encoding": _ui_enc(enc)},
                "key_note": "check the leading 12/16 bytes for a nonce and the trailing 16 for a GCM tag",
                "cli": "crypto-cli.py dec --structure iv_ct --mode CTR --key hex:<key> --data '<ct>'",
            })
            for ivl, tagl in ((12, 16), (16, 16)):
                if len(raw) > ivl + tagl:
                    H.append({
                        "name": "IV(%d) + ciphertext + tag(%d) — AEAD (structure=iv_ct_tag)" % (ivl, tagl),
                        "confidence": 55,
                        "detail": "consistent with AES-GCM: %d-byte nonce, %d-byte ciphertext, %d-byte tag"
                                  % (ivl, len(raw) - ivl - tagl, tagl),
                        "reencrypt": {"engine": "aes", "ciphertextStructure": "iv_ct_tag", "mode": "GCM",
                                      "ivLength": str(ivl), "gcmTagLength": str(tagl * 8),
                                      "encoding": _ui_enc(enc)},
                        "key_note": "GCM verifies integrity — a wrong key fails loudly, which makes "
                                    "key guesses easy to confirm",
                        "cli": "crypto-cli.py dec --structure iv_ct_tag --mode GCM --iv-length %d "
                               "--key hex:<key> --data '<ct>'" % ivl,
                    })

    # ---- RSA block sizes ----
    for bits in (1024, 2048, 3072, 4096):
        n = bits // 8
        if len(raw) == n or (len(raw) % n == 0 and len(raw) // n <= 8 and len(raw) > n):
            H.append({
                "name": "raw RSA block%s (%d-bit key)" % ("s" if len(raw) > n else "", bits),
                "confidence": 80 if len(raw) == n else 70,
                "detail": "%d bytes = %d × %d-byte modulus block(s)" % (len(raw), len(raw) // n, n),
                "reencrypt": {"engine": "rsa", "encryptionScheme": "PKCS1", "encoding": _ui_enc(enc)},
                "key_note": "you need the private key: extract it if embedded, otherwise swap the app's "
                            "public key for yours (see key-exchange-mitm.md)",
                "cli": "crypto-cli.py dec --engine rsa --priv file:priv.pem --rsa-scheme pkcs1 --data '<ct>'",
            })
            break

    H.sort(key=lambda h: -h["confidence"])
    return a


def _cross_sample_jose(values) -> list:
    """Compare JWE tokens segment by segment — which piece is reused tells you what to capture."""
    out = []
    cols = list(zip(*[v.strip().split(".") for v in values]))
    labels = ["protected header", "wrapped key (CEK)", "IV", "ciphertext", "tag"]
    for i, (label, col) in enumerate(zip(labels, cols)):
        uniq = len(set(col))
        if i == 0:
            out.append("protected header is %s across samples" % ("identical" if uniq == 1 else
                                                                  "%d different values" % uniq))
        elif i == 1:
            if all(not c.strip() for c in col):
                out.append("**the wrapped-key segment is empty in every sample** → the key comes from a "
                           "separate key exchange, not from the message. Look for a handshake endpoint "
                           "(`/init`, `/handshake`, `/keys`, a key inside the login response) and take "
                           "the key there — see key-exchange-mitm.md.")
            elif uniq == 1:
                out.append("**the wrapped key is identical in every sample** → the CEK is per-session, "
                           "not per-message. Capture it once and every message of that session decrypts "
                           "with it.")
            else:
                out.append("the wrapped key changes every message → the CEK is per-message. Either unwrap "
                           "it (swap the app's RSA public key for yours) or hook the CEK at runtime and "
                           "re-read it per request.")
        elif i == 2 and uniq == 1:
            out.append("**the IV/nonce is identical in every sample** — fixed IV. With CTR/GCM that is "
                       "keystream reuse: report it, and XOR of two ciphertexts leaks plaintext.")
        elif i == 4 and uniq == 1 and col[0]:
            out.append("the tag segment is identical across samples — it is probably not a real "
                       "authentication tag (or the content mode is not AEAD).")
    if all(not c for c in cols[4]):
        out.append("the tag segment is empty → non-AEAD content encryption (CTR/CBC in a JWE wrapper); "
                   "Re:Encrypt re-uses the captured tag segment verbatim on re-encrypt.")
    return out


def _jose_header(seg: str):
    try:
        h = json.loads(b64u_dec(seg))
        return h if isinstance(h, dict) and ("alg" in h or "enc" in h) else None
    except Exception:
        return None


def _enc_to_mode(enc):
    if not enc:
        return None
    m = re.fullmatch(r"A(?:128|192|256)(GCM|CTR|CBC|CFB|OFB)(?:-HS\d+)?", str(enc).upper())
    return m.group(1) if m else None


def _ui_enc(enc):
    return {"base64": "Base64", "base64url": "Base64URL", "hex": "Hex", "raw": "Raw"}[enc]


def _ecb_repeats(raw: bytes) -> int:
    blocks = [raw[i:i + BLOCK] for i in range(0, len(raw) - len(raw) % BLOCK, BLOCK)]
    c = Counter(blocks)
    return sum(v - 1 for v in c.values() if v > 1)


# ---------------------------------------------------------------------------
# cross-sample analysis
# ---------------------------------------------------------------------------

def cross_sample(values) -> list:
    out = []
    if len(values) < 2:
        return out
    if all(len(v.strip().split(".")) == 5 for v in values):
        return _cross_sample_jose(values)
    if len(set(values)) == 1:
        return ["**all %d samples are byte-identical** — deterministic encryption (ECB, or a fixed "
                "IV/nonce), or the field simply doesn't depend on the request. Replay is likely "
                "possible; report it." % len(values)]
    decoded = []
    for v in values:
        enc, raw = try_decode(v.strip().strip('"'))
        decoded.append((enc, raw))
    encs = {e for e, _ in decoded}
    if len(encs) > 1:
        out.append("samples disagree on outer encoding (%s) — check they are the same field" % ", ".join(encs))
    raws = [r for _, r in decoded]

    pre = os.path.commonprefix(raws)
    if len(pre) >= 4:
        out.append("**constant %d-byte prefix** `%s` — a static IV, a key id, a version byte or a fixed "
                   "header. If it is 16 bytes, the IV is NOT random: treat it as a fixed IV (and as a "
                   "finding)." % (len(pre), pre[:24].hex()))
    rev = [r[::-1] for r in raws]
    suf = os.path.commonprefix(rev)[::-1]
    if len(suf) >= 4:
        out.append("constant %d-byte suffix `%s` — a fixed tag/checksum or padding of a constant "
                   "plaintext tail" % (len(suf), suf[-24:].hex()))

    lens = [len(r) for r in raws]
    if all(l % BLOCK == 0 for l in lens):
        out.append("every sample is block-aligned (%s) → block mode with padding (CBC/ECB)"
                   % ", ".join(map(str, sorted(set(lens))[:6])))
    elif not any(l % BLOCK == 0 for l in lens):
        out.append("no sample is block-aligned (%s) → stream mode (CTR/GCM/CFB/OFB) or an added "
                   "IV/tag of non-multiple size" % ", ".join(map(str, sorted(set(lens))[:6])))

    dups = [v for v, n in Counter(values).items() if n > 1]
    if dups:
        out.append("**%d value(s) repeat verbatim across samples** — deterministic encryption "
                   "(ECB or a fixed IV/nonce). Replay is likely possible; report it." % len(dups))

    # nonce reuse across GCM-looking samples
    if len({r[:12] for r in raws}) == 1 and len(raws) > 1 and len(pre) >= 12:
        out.append("identical leading 12 bytes across samples — if this is a GCM nonce, nonce reuse "
                   "breaks the mode's security outright (report it).")
    return out


# ---------------------------------------------------------------------------
# Re:Encrypt pattern suggestion
# ---------------------------------------------------------------------------

RSA_SIZES = {128: 1024, 256: 2048, 384: 3072, 512: 4096}


def wrapped_key_pairs(report) -> list:
    """Spot 'wrapped key + payload' inside one message: a modulus-sized field next to a longer one.

    RSA is slow and size-limited, so a field that is *exactly* a modulus size is almost never a
    payload — it is a symmetric key wrapped for the other side. Saying so turns two confusing
    ciphertexts into one clear plan.
    """
    out = []
    by_msg = {}
    for e in report:
        ident = (e["location"].split(" of ", 1)[-1]) if " of " in e["location"] else e["location"]
        by_msg.setdefault(ident, []).append(e)
    for ident, entries in by_msg.items():
        if len(entries) < 2:
            continue
        wrapped = [e for e in entries if e["analysis"]["decoded_length"] in RSA_SIZES
                   and not e["analysis"].get("jose_segments")]
        payloads = [e for e in entries
                    if e["analysis"]["decoded_length"] not in RSA_SIZES
                    and e["analysis"]["decoded_length"] >= 16]
        for w in wrapped:
            for pl in payloads:
                out.append({
                    "message": ident,
                    "wrapped": w["name"] or w["kind"], "wrapped_kind": w["kind"],
                    "bits": RSA_SIZES[w["analysis"]["decoded_length"]],
                    "payload": pl["name"] or pl["kind"], "payload_kind": pl["kind"],
                    "payload_bytes": pl["analysis"]["decoded_length"],
                })
    return out


def integrity_fields(cands) -> list:
    """Fields that look like a MAC/nonce/timestamp — not decryptable, but they gate tampering."""
    seen: dict = {}
    for c in cands:
        if not c.name or not SIG_NAME.search(c.name):
            continue
        v = c.value.strip()
        enc, raw = try_decode(v)
        desc = DIGEST_LEN.get(len(raw)) if enc != "raw" else None
        if desc:
            why = "%s of %d bytes → %s" % (enc, len(raw), desc)
        elif re.fullmatch(r"\d{10,13}", v):
            why = "epoch timestamp"
        elif len(v) <= 64:
            why = "short opaque value (%d chars)" % len(v)
        else:
            continue
        key = (c.kind, c.name)
        entry = seen.setdefault(key, {"location": c.where, "name": c.name, "why": why, "values": []})
        if v not in entry["values"] and len(entry["values"]) < 3:
            entry["values"].append(v)
    return list(seen.values())


def reencrypt_pattern(c: Candidate) -> dict:
    """Map a candidate location to a Re:Encrypt capture pattern (group 1 = the ciphertext)."""
    if c.kind == "header":
        return {"patternType": "Header", "patternInput": c.name,
                "captureRegex": "(?i)%s: (.*)" % re.escape(c.name)}
    if c.kind in ("url_param", "form_param"):
        return {"patternType": "Parameter (URL-encoded)", "patternInput": c.name,
                "captureRegex": "%s=(.*?)(?:&|$)" % re.escape(c.name)}
    if c.kind == "json_param":
        return {"patternType": "Parameter (JSON)", "patternInput": c.name,
                "captureRegex": '"%s":"(.*?)"' % re.escape(c.name)}
    if c.kind == "cookie":
        return {"patternType": "Custom Regex", "patternInput": c.name,
                "captureRegex": r"%s=([^;\r\n]*)" % re.escape(c.name)}
    if c.kind == "body":
        return {"patternType": "Whole Body", "patternInput": "",
                "captureRegex": r"(?s)(?<=\r\n\r\n)(.+)"}
    return {"patternType": "Custom Regex", "patternInput": "", "captureRegex": "(<your regex here>)"}


# ---------------------------------------------------------------------------
# input loading
# ---------------------------------------------------------------------------

def load_inputs(args) -> list:
    cands: list[Candidate] = []
    if args.value:
        for v in args.value:
            cands.append(Candidate(v, "value from --value", "value"))
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files.extend(os.path.join(p, f) for f in sorted(os.listdir(p))
                         if os.path.isfile(os.path.join(p, f)))
        else:
            files.append(p)
    for f in files:
        try:
            with open(f, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("skip %s: %s" % (f, exc), file=sys.stderr)
            continue
        base = os.path.basename(f)
        if f.lower().endswith(".har") or '"log"' in text[:200]:
            try:
                cands.extend(candidates_from_har(text, args.host))
                continue
            except ValueError:
                pass
        if re.match(r"^[A-Z]+ \S+ HTTP/|^HTTP/\d", text.strip()):
            cands.extend(candidates_from_http(text, base))
        elif text.strip()[:1] in "{[":
            cands.extend(candidates_from_body(text, base))
        else:
            for line in text.splitlines():
                if line.strip():
                    cands.append(Candidate(line.strip(), "line of %s" % base, "value", None, base))
    if not sys.stdin.isatty() and not cands:
        data = sys.stdin.read()
        if data.strip():
            if re.match(r"^[A-Z]+ \S+ HTTP/", data.strip()):
                cands.extend(candidates_from_http(data, "stdin"))
            else:
                cands.append(Candidate(data.strip(), "stdin", "value"))
    return cands


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="raw HTTP files, .har exports, value lists, or directories")
    ap.add_argument("--value", action="append", help="analyze this literal value (repeatable)")
    ap.add_argument("--host", help="HAR only: keep entries whose URL contains this host")
    ap.add_argument("--top", type=int, default=6, help="how many candidate fields to report (default 6)")
    ap.add_argument("--min-score", type=float, default=25.0, help="drop candidates below this score")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    cands = load_inputs(args)
    if not cands:
        ap.error("no input: pass files, --value, or pipe a request on stdin")

    scored = [(score_candidate(c), c) for c in cands]
    scored = [(s, c) for s, c in scored if s >= args.min_score]
    if not scored:
        print("No field looks encrypted (all candidates scored below %.0f).\n"
              "Sanity-check: is the body plain JSON? is only *part* of it encrypted? is it just "
              "base64/gzip? Re-run with --min-score 0 to see everything." % args.min_score)
        return 0

    # group identical locations across samples so cross-sample analysis has something to chew on
    groups: dict = {}
    for s, c in scored:
        groups.setdefault(c.key(), {"score": 0, "cand": c, "values": []})
        g = groups[c.key()]
        g["score"] = max(g["score"], s)
        g["values"].append(c.value)

    ranked = sorted(groups.values(), key=lambda g: -g["score"])[: args.top]
    report = []
    for g in ranked:
        c = g["cand"]
        vals = g["values"]
        entry = {
            "location": c.where,
            "kind": c.kind,
            "name": c.name,
            "samples": len(vals),
            "score": round(g["score"], 1),
            "reencrypt_pattern": reencrypt_pattern(c),
            "analysis": analyze_value(vals[0]),
            "cross_sample": cross_sample(vals),
        }
        report.append(entry)

    integrity = integrity_fields(cands)
    pairs = wrapped_key_pairs(report)
    if args.json:
        print(json.dumps({"candidates": report, "integrity_fields": integrity,
                          "wrapped_key_pairs": pairs}, indent=2))
        return 0

    print("# Ciphertext analysis\n")
    print("%d candidate field(s) from %d extracted value(s).\n" % (len(ranked), len(cands)))
    for i, e in enumerate(report, 1):
        a = e["analysis"]
        print("## %d. %s  _(score %.0f, %d sample%s)_" % (i, e["location"], e["score"], e["samples"],
                                                          "" if e["samples"] == 1 else "s"))
        print("")
        print("- value: `%s`" % a["value_preview"])
        if a.get("jose_segments"):
            print("- **JOSE compact token** · ciphertext segment %d bytes · %s"
                  % (a["decoded_length"], "block-aligned" if a["block_aligned"] else "not block-aligned"))
        else:
            print("- outer encoding: **%s** → %d bytes · entropy %.2f bits/byte · %s"
                  % (a["outer_encoding"], a["decoded_length"], a["entropy"],
                     "block-aligned" if a["block_aligned"] else "not block-aligned"))
        p = e["reencrypt_pattern"]
        print("- Re:Encrypt pattern: type **%s**, input `%s`, regex `%s`"
              % (p["patternType"], p["patternInput"], p["captureRegex"]))
        print("")
        if a["hypotheses"]:
            print("### Hypotheses (most likely first)")
            for h in a["hypotheses"]:
                print("")
                print("**%s** — confidence %d%%" % (h["name"], h["confidence"]))
                print("- %s" % h["detail"])
                print("- key: %s" % h["key_note"])
                if h.get("reencrypt"):
                    print("- Re:Encrypt engine params: `%s`" % json.dumps(h["reencrypt"]))
                if h.get("cli"):
                    print("- try: `%s`" % h["cli"])
        if a["observations"]:
            print("")
            print("### Observations")
            for o in a["observations"]:
                print("- %s" % o)
        if e["cross_sample"]:
            print("")
            print("### Across the %d samples of this field" % e["samples"])
            for o in e["cross_sample"]:
                print("- %s" % o)
        print("")
    if pairs:
        print("## Hybrid detected: a wrapped key next to a payload")
        print("")
        for pr in pairs:
            print("- in **%s**: `%s` is exactly %d bytes (one %d-bit RSA block) while `%s` carries "
                  "%d bytes → wrapped key + payload."
                  % (pr["message"], pr["wrapped"], pr["bits"] // 8, pr["bits"], pr["payload"],
                     pr["payload_bytes"]))
        print("")
        print("A field of *exactly* a modulus size is a **wrapped symmetric key**, not a payload — RSA "
              "is too slow and too size-limited to carry a body. So: get the symmetric key out of that "
              "field (a hardcoded private key if the app ships one, otherwise swap the public key in "
              "the exchange — key-exchange-mitm.md), then decrypt the other field with it. Do not try "
              "to brute-force the payload field with candidate keys; it is not keyed by anything in the "
              "artifact.")
        print("")
    if integrity:
        print("## Integrity / freshness fields (handle these or your edits get rejected)")
        print("")
        for f in integrity:
            print("- **%s** — %s · %s" % (f["name"], f["why"], f["location"]))
            for v in f["values"]:
                print("  - `%s`" % (v[:80] + ("…" if len(v) > 80 else "")))
        print("")
        print("Work out what each one is computed over (usually the ciphertext or the plaintext body, "
              "sometimes plus a URL/timestamp/nonce) and re-compute it after every edit — see "
              "references/integrity-and-signatures.md.")
        print("")
    print("---")
    print("Next: pick the top hypothesis, then get the key in this order — static-key-hunt.md "
          "(shipped in the app) → key-exchange-mitm.md (take it at the proxy) → patch-the-client.md "
          "→ runtime-key-capture.md (last resort). Confirm with crypto-cli.py: "
          "A hypothesis is only real once a captured sample decrypts to plaintext you recognise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
