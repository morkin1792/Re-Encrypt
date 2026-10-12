#!/usr/bin/env python3
"""
crypto-cli.py — decrypt/encrypt one app-traffic payload from the command line.

Jobs:
  1. **Prove a hypothesis.** Take a captured ciphertext + a candidate key and see whether plaintext
     falls out. Nothing else in this skill counts as confirmation.
  2. **Find the hypothesis** (`solve`) when you don't have one: sweep encoding × structure × mode ×
     IV convention × key interpretation and rank by how text-like the output is.
  3. **Be the worker behind Re:Encrypt's custom commands** (`{DATA}` / `{FILE}`), or behind an
     mitmproxy addon / your own script when Burp isn't in play.
  4. **Serve the key-swap route** (`keygen`, `derive`): mint the pair you substitute into an app's key
     exchange, and derive ECDH/X25519 session keys with the app's own KDF.

It writes the result to stdout with **no added newline**, reads the payload from `--in-file` or
`--data` or stdin, and exits non-zero with a one-line reason on failure — exactly what a proxy
extension wants from a shell command.

Backends, in order of preference: pycryptodome, `cryptography`, then the `openssl` CLI. Only AES-GCM
needs one of the two libraries; everything else works with openssl alone.

Examples
--------
  # AES-256-CBC, IV prepended to the ciphertext, base64 on the wire
  crypto-cli.py dec --mode CBC --structure iv_ct --key hex:00112233...  --data "$CT"

  # same, as a Re:Encrypt Decrypt Command / Encrypt Command pair
  #   dec: python3 crypto-cli.py dec --mode CBC --structure iv_ct --key file:/tmp/aes.key --in-file {FILE}
  #   enc: python3 crypto-cli.py enc --mode CBC --structure iv_ct --key file:/tmp/aes.key --in-file {FILE}
  # (file: is re-read on every call, so a rotating session key keeps working unattended)

  # session keys from a key log written by whatever captured them (see --key-log)
  crypto-cli.py dec --structure jwe --key-log ./key --session 519e1101-… --in-file body.json
  crypto-cli.py keys --key-log ./key --session 519e1101-…      # what keys did that session have?

  # JWE compact, RSA-wrapped CEK, AES-256-CTR content encryption (a common hybrid)
  crypto-cli.py dec --structure jwe --priv file:key.pem --jwe-state /tmp/jwe.json --in-file {FILE}
  crypto-cli.py enc --structure jwe --priv file:key.pem --jwe-state /tmp/jwe.json --in-file {FILE}

  # pure RSA body
  crypto-cli.py dec --engine rsa --priv file:priv.pem --rsa-scheme oaep-sha256 --data "$CT"

  # don't know the parameters yet? sweep them against a captured sample
  crypto-cli.py solve --key-candidates triage-keys.txt --expect '"cpf"' --in-file ct.txt

  # keys for a key swap, and ECDH/X25519 schemes where no key is ever transmitted
  crypto-cli.py keygen --alg x25519 --out keys/mitm.pem
  crypto-cli.py derive --priv file:keys/mitm.pem --peer-pub file:peer-pub.pem --hkdf sha256

  # is my environment able to do this at all?
  crypto-cli.py selftest

Material specs (--key/--iv/--cek/--priv/--pub) are `[<source>:][<format>:]<value>`:
  sources  text (default) · file · env · cmd        formats  hex · b64 · b64u · utf8 · auto (default)
  e.g.  hex:0011..  ·  b64:AAAA..  ·  file:/tmp/aes.key  ·  file:hex:/tmp/aes.key  ·  env:AESKEY
        ·  cmd:"adb shell cat /data/local/tmp/key.hex"

Key logs (`--key-log FILE`) hold one line per key an exchange handed out:

    <timestamp>: <key> [<session-id>]
    2026-09-01T14:28:50: pXk4qZDS3VLQPyPk832i350ykiEL1jOf bcd7c542-e126-40c1-a7d0-bf8069180c8f

Resolution order: `--key` › `--session` (newest key of that session) › a session id found in the
input itself › newest key in the log (with a warning). Apps that renew the key mid-session give one
session several keys — for an older capture, run `keys --session <sid>` and pass the right one.
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
import tempfile

MODES = ("CBC", "ECB", "CTR", "GCM", "CFB", "OFB")
STRUCTURES = ("raw", "iv_ct", "iv_ct_tag", "openssl", "jwe")
ENCODINGS = ("base64", "base64url", "hex", "raw")
BLOCK = 16


SOLVING = False          # set during `solve`: failures are expected, so don't narrate them


def die(msg: str, code: int = 2):
    if not SOLVING:
        print("crypto-cli: %s" % msg, file=sys.stderr)
    sys.exit(code)


QUIET = os.environ.get("CRYPTO_CLI_QUIET") == "1"


def note(msg: str):
    """Diagnostics go to stderr — but Re:Encrypt merges stderr into the command output, so pass
    --quiet in a proxy command (the generated runbook commands already do)."""
    if not QUIET:
        print("crypto-cli: %s" % msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------

def dec_outer(s: str, enc: str) -> bytes:
    s = s.strip() if enc != "raw" else s
    if enc == "raw":
        return s.encode("latin-1")
    if enc == "hex":
        return binascii.unhexlify(re.sub(r"\s+", "", s))
    pad = "=" * (-len(s) % 4)
    if enc == "base64url":
        return base64.urlsafe_b64decode(s + pad)
    return base64.b64decode(s + pad)


def enc_outer(b: bytes, enc: str, pad: bool = True) -> str:
    if enc == "raw":
        return b.decode("latin-1")
    if enc == "hex":
        return b.hex()
    out = (base64.urlsafe_b64encode if enc == "base64url" else base64.b64encode)(b).decode()
    return out if pad else out.rstrip("=")


def sniff_key_format(text: str) -> str:
    """Guess how a key literal encodes its bytes. Ambiguity is real here, so it is announced.

    Order matters: a 32-character printable literal is far more often 32 raw UTF-8 bytes (AES-256 keyed
    by a printable string — very common in hand-rolled schemes) than base64 of 24 bytes.
    """
    t = text.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t) and len(t) // 2 in (16, 24, 32):
        return "hex"
    if len(t) in (16, 24, 32) and re.fullmatch(r"[\x21-\x7e]+", t):
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t):
            note("key %r could be UTF-8 (%d bytes) or base64 (%d bytes) — using UTF-8; force with "
                 "b64:… if a decrypt fails" % (t[:8] + "…", len(t), len(t) * 3 // 4))
        return "utf8"
    for fmt in ("base64", "base64url"):
        try:
            if len(dec_outer(t, fmt)) in (16, 24, 32):
                return fmt
        except Exception:
            pass
    return "utf8"


def sniff_encoding(s: str) -> str:
    t = s.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t) and len(t) >= 16:
        return "hex"
    if re.search(r"[-_]", t) and not re.search(r"[+/]", t):
        return "base64url"
    return "base64"


# ---------------------------------------------------------------------------
# material loading (keys, IVs, PEMs)
# ---------------------------------------------------------------------------
SOURCES = ("text", "file", "env", "cmd")
FORMATS = ("hex", "b64", "b64u", "base64", "base64url", "utf8", "raw", "auto")


def load_material(spec: str, want: str = "bytes"):
    """Resolve a material spec to bytes (want='bytes') or to its raw text (want='text')."""
    if spec is None:
        return None
    source, fmt = "text", "auto"
    rest = spec
    for _ in range(2):
        m = re.match(r"([A-Za-z0-9]+):(.*)\Z", rest, re.S)
        if not m:
            break
        tok, tail = m.group(1).lower(), m.group(2)
        if tok in SOURCES and source == "text":
            source, rest = tok, tail
        elif tok in FORMATS and fmt == "auto":
            fmt, rest = tok, tail
        else:
            break

    if source == "file":
        with open(os.path.expanduser(rest), "rb") as fh:
            raw = fh.read()
    elif source == "env":
        val = os.environ.get(rest)
        if val is None:
            die("env var %s is not set" % rest)
        raw = val.encode()
    elif source == "cmd":
        p = subprocess.run(rest, shell=True, capture_output=True)
        if p.returncode != 0:
            die("key command failed (%d): %s" % (p.returncode, p.stderr.decode("utf-8", "replace").strip()))
        raw = p.stdout
    else:
        raw = rest.encode("utf-8")

    if want == "text":
        return raw
    text = raw.decode("utf-8", "replace").strip()
    if fmt == "auto":
        fmt = sniff_key_format(text)
    if fmt in ("utf8", "raw"):
        return text.encode("utf-8")
    if fmt == "hex":
        return binascii.unhexlify(re.sub(r"\s+", "", text))
    if fmt in ("b64", "base64"):
        return base64.b64decode(text + "=" * (-len(text) % 4))
    if fmt in ("b64u", "base64url"):
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    die("unknown key format %r" % fmt)


# ---------------------------------------------------------------------------
# key logs — several shapes, because whoever captured the key chose the format
# ---------------------------------------------------------------------------
KEYLOG_SHAPES = [
    # <ts>: <key> [<session>]   /   <ts>,<key>[,<session>]   (a bare ':' would split the timestamp)
    re.compile(r"^(?P<time>\S+?)(?::\s+|\s*[,;\t]\s*)(?P<key>[^\s,;\t]+)"
               r"(?:[\s,;\t]+(?P<session>[^\s,;\t]+))?\s*$"),
    re.compile(r"^(?P<time>\S+)\s+(?P<key>\S+)(?:\s+(?P<session>\S+))?$"),
    # key=<k> session=<s> time=<t>, in any order
    re.compile(r"(?i)(?:^|[\s,;])key\s*[=:]\s*(?P<key>[^\s,;]+)"),
    # a bare key per line
    re.compile(r"^(?P<key>\S{8,})$"),
]
KV = re.compile(r"(?i)(?:^|[\s,;])(?P<k>[a-z_-]+)\s*[=:]\s*(?P<v>[^\s,;]+)")
# name of anything that identifies a session/handshake, and a value that could be its id
SESSION_KEYS = re.compile(r"(?i)(session|handshake|conversation|correlation|exchange|sid|token[_-]?id)")
SESSION_VALUE = r"[A-Za-z0-9_.:-]{8,80}"


def load_keylog(path: str) -> list:
    """Parse a key log tolerantly: '<ts>: <key> [<session>]', JSON lines, k=v lines, bare keys."""
    out = []
    try:
        with open(os.path.expanduser(path)) as fh:
            raw_lines = fh.read().splitlines()
    except OSError as exc:
        die("cannot read --key-log %s: %s" % (path, exc))
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entry = None
        if line.startswith("{"):                                   # JSON line
            try:
                obj = json.loads(line)
                key = next((obj[k] for k in ("key", "aesKey", "cek", "value", "k") if obj.get(k)), None)
                if key:
                    entry = {"time": str(next((obj[k] for k in ("time", "ts", "timestamp", "date")
                                               if obj.get(k)), "")),
                             "key": str(key),
                             "session": str(next((v for k, v in obj.items()
                                                  if SESSION_KEYS.search(k) and v), ""))}
            except ValueError:
                entry = None
        if entry is None and KV.search(line):                      # k=v shape
            kv = {m.group("k").lower(): m.group("v") for m in KV.finditer(line)}
            key = next((kv[k] for k in ("key", "aeskey", "cek", "value", "k") if kv.get(k)), None)
            if key:
                entry = {"time": next((kv[k] for k in ("time", "ts", "timestamp", "date")
                                       if kv.get(k)), ""),
                         "key": key,
                         "session": next((v for k, v in kv.items() if SESSION_KEYS.search(k)), "")}
        if entry is None:
            for rx in KEYLOG_SHAPES:
                m = rx.match(line)
                if m and m.groupdict().get("key"):
                    g = m.groupdict()
                    entry = {"time": g.get("time") or "", "key": g["key"], "session": g.get("session") or ""}
                    break
        if entry:
            out.append(entry)
    if not out:
        die("--key-log %s: no key lines recognised. Accepted shapes: '<ts>: <key> [<session>]', "
            "'<ts> <key> [<session>]', 'key=… session=…', one JSON object per line, or a bare key "
            "per line." % path)
    return out


def sniff_session(text: str, pattern: str = None):
    """Find a session/handshake identifier in a raw message or body."""
    if not text:
        return None
    if pattern:
        m = re.search(pattern, text)
        return (m.group(1) if m.lastindex else m.group(0)) if m else None
    # header or JSON/query field whose NAME looks session-ish; take its value
    for rx in (r"(?im)^[a-z0-9_-]*%s[a-z0-9_-]*\s*:\s*\"?(%s)" % (SESSION_KEYS.pattern, SESSION_VALUE),
               r"(?i)\"[a-z0-9_-]*%s[a-z0-9_-]*\"\s*:\s*\"(%s)\"" % (SESSION_KEYS.pattern, SESSION_VALUE),
               r"(?i)[?&][a-z0-9_-]*%s[a-z0-9_-]*=(%s)" % (SESSION_KEYS.pattern, SESSION_VALUE)):
        m = re.search(rx, text)
        if m:
            return m.group(m.lastindex)
    return None


def resolve_keylog(args, payload_text: str):
    """Pick a key from the log: --session, else a session id in the payload, else newest."""
    keys = load_keylog(args.key_log)
    sid = args.session or sniff_session(payload_text, getattr(args, "session_regex", None))
    if sid:
        hits = [k for k in keys if k["session"].lower() == sid.lower()]
        if not hits:
            die("no key for session %s in %s — capture that session's exchange first "
                "(`keys --key-log %s` lists what is there)" % (sid, args.key_log, args.key_log))
        if len(hits) > 1:
            note("session %s has %d keys (renewal); using the newest (%s). For an older capture pick "
                 "one with --key." % (sid, len(hits), hits[-1]["time"]))
        return hits[-1]
    newest = keys[-1]
    note("no --session and none found in the payload — falling back to the NEWEST key in %s (%s, "
         "session %s). Pass --session/--key if that is not the right one."
         % (args.key_log, newest["time"], newest["session"] or "?"))
    return newest


# ---------------------------------------------------------------------------
# AES backends
# ---------------------------------------------------------------------------
_BACKEND = None


def backend():
    global _BACKEND
    if _BACKEND:
        return _BACKEND
    try:
        import Crypto.Cipher.AES  # noqa: F401
        _BACKEND = "pycryptodome"
    except ImportError:
        try:
            import cryptography.hazmat.primitives.ciphers  # noqa: F401
            _BACKEND = "cryptography"
        except ImportError:
            _BACKEND = "openssl" if _which("openssl") else None
    if _BACKEND is None:
        die("no crypto backend: install pycryptodome (pip install pycryptodome) or put openssl on PATH")
    return _BACKEND


def _which(x):
    from shutil import which
    return which(x)


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, strict: bool) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= BLOCK and data.endswith(bytes([n]) * n):
        return data[:-n]
    if strict:
        die("PKCS#7 unpad failed — wrong key/IV/mode, or the payload is not padded (try --padding none)")
    return data


def aes_transform(key: bytes, iv: bytes, data: bytes, mode: str, encrypt: bool,
                  aad: bytes = None, tag: bytes = None, tag_bits: int = 128, cfb_segment: int = 128):
    """Raw AES on already-parsed pieces. Returns bytes (encrypt+GCM returns ct||tag)."""
    if len(key) not in (16, 24, 32):
        die("key is %d bytes; AES needs 16, 24 or 32 (check --key format)" % len(key))
    if mode not in MODES:
        die("unsupported mode %s" % mode)
    if mode in ("CBC", "ECB") and not encrypt and len(data) % BLOCK:
        note("ciphertext is %d bytes, not a multiple of 16 — %s cannot be right" % (len(data), mode))
    be = backend()

    if be == "pycryptodome":
        from Crypto.Cipher import AES
        kw = {}
        if mode == "ECB":
            c = AES.new(key, AES.MODE_ECB)
        elif mode == "CBC":
            c = AES.new(key, AES.MODE_CBC, iv)
        elif mode == "CTR":
            from Crypto.Util import Counter
            c = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))
        elif mode == "GCM":
            c = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=tag_bits // 8)
        elif mode == "CFB":
            c = AES.new(key, AES.MODE_CFB, iv, segment_size=cfb_segment)
        else:
            c = AES.new(key, AES.MODE_OFB, iv)
        del kw
        if mode == "GCM":
            if aad:
                c.update(aad)
            if encrypt:
                ct, t = c.encrypt_and_digest(data)
                return ct + t
            try:
                return c.decrypt_and_verify(data[:-tag_bits // 8], data[-tag_bits // 8:])
            except ValueError:
                die("GCM tag check failed — wrong key, IV or AAD")
        return c.encrypt(data) if encrypt else c.decrypt(data)

    if be == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as m
        if mode == "GCM":
            if encrypt:
                c = Cipher(algorithms.AES(key), m.GCM(iv, min_tag_length=tag_bits // 8)).encryptor()
                if aad:
                    c.authenticate_additional_data(aad)
                ct = c.update(data) + c.finalize()
                return ct + c.tag[: tag_bits // 8]
            tl = tag_bits // 8
            c = Cipher(algorithms.AES(key), m.GCM(iv, data[-tl:], min_tag_length=tl)).decryptor()
            if aad:
                c.authenticate_additional_data(aad)
            try:
                return c.update(data[:-tl]) + c.finalize()
            except Exception:
                die("GCM tag check failed — wrong key, IV or AAD")
        try:                          # CFB/OFB moved out of primitives in cryptography 49
            from cryptography.hazmat.decrepit.ciphers import modes as legacy
        except ImportError:
            legacy = m
        mode_obj = {"CBC": lambda: m.CBC(iv), "ECB": lambda: m.ECB(), "CTR": lambda: m.CTR(iv),
                    "CFB": lambda: (legacy.CFB(iv) if cfb_segment == 128 else legacy.CFB8(iv)),
                    "OFB": lambda: legacy.OFB(iv)}[mode]()
        c = Cipher(algorithms.AES(key), mode_obj)
        op = c.encryptor() if encrypt else c.decryptor()
        return op.update(data) + op.finalize()

    # openssl CLI
    if mode == "GCM":
        die("AES-GCM needs a python crypto library: pip install pycryptodome")
    name = "aes-%d-%s" % (len(key) * 8, {"CBC": "cbc", "ECB": "ecb", "CTR": "ctr",
                                         "CFB": "cfb" if cfb_segment == 128 else "cfb8",
                                         "OFB": "ofb"}[mode])
    cmd = ["openssl", "enc", "-" + name, "-K", key.hex(), "-nopad"]
    if mode != "ECB":
        cmd += ["-iv", iv.hex()]
    if not encrypt:
        cmd.append("-d")
    p = subprocess.run(cmd, input=data, capture_output=True)
    if p.returncode != 0:
        die("openssl %s failed: %s" % (name, p.stderr.decode("utf-8", "replace").strip()))
    return p.stdout


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------
SCHEMES = {"pkcs1": 11, "oaep-sha1": 42, "oaep-sha256": 66}


def rsa_op(data: bytes, key_spec: str, scheme: str, encrypt: bool) -> bytes:
    """RSA over possibly-multiple blocks (apps chunk long bodies)."""
    pem = load_material(key_spec, want="text")
    be = None
    try:
        import Crypto.PublicKey.RSA  # noqa: F401
        be = "pycryptodome"
    except ImportError:
        try:
            import cryptography.hazmat.primitives.serialization  # noqa: F401
            be = "cryptography"
        except ImportError:
            be = "openssl" if _which("openssl") else None
    if be is None:
        die("RSA needs pycryptodome, cryptography, or openssl on PATH")

    if be == "pycryptodome":
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
        from Crypto.Hash import SHA1, SHA256
        k = RSA.import_key(pem)
        ksize = k.size_in_bytes()
        if scheme == "pkcs1":
            c = PKCS1_v1_5.new(k)
            one = (lambda b: c.encrypt(b)) if encrypt else (lambda b: c.decrypt(b, None))
        else:
            h = SHA256 if scheme == "oaep-sha256" else SHA1
            c = PKCS1_OAEP.new(k, hashAlgo=h)
            one = (lambda b: c.encrypt(b)) if encrypt else (lambda b: c.decrypt(b))
        return _rsa_chunks(data, ksize, scheme, encrypt, one)

    if be == "cryptography":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        if encrypt:
            k = serialization.load_pem_public_key(pem)
            ksize = k.key_size // 8
        else:
            k = serialization.load_pem_private_key(pem, password=None)
            ksize = k.key_size // 8
        if scheme == "pkcs1":
            pad = padding.PKCS1v15()
        else:
            algo = hashes.SHA256() if scheme == "oaep-sha256" else hashes.SHA1()
            pad = padding.OAEP(mgf=padding.MGF1(algorithm=algo), algorithm=algo, label=None)
        one = (lambda b: k.encrypt(b, pad)) if encrypt else (lambda b: k.decrypt(b, pad))
        return _rsa_chunks(data, ksize, scheme, encrypt, one)

    # openssl CLI
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        keyfile = fh.name
    try:
        ksize = _openssl_key_size(keyfile, encrypt)
        opts = ["-pkeyopt", "rsa_padding_mode:%s" % ("pkcs1" if scheme == "pkcs1" else "oaep")]
        if scheme.startswith("oaep"):
            opts += ["-pkeyopt", "rsa_oaep_md:%s" % ("sha256" if scheme == "oaep-sha256" else "sha1")]
        base = ["openssl", "pkeyutl", "-encrypt" if encrypt else "-decrypt", "-inkey", keyfile] + opts
        if encrypt:
            base.append("-pubin")

        def one(b):
            p = subprocess.run(base, input=b, capture_output=True)
            if p.returncode != 0:
                die("openssl pkeyutl failed: %s" % p.stderr.decode("utf-8", "replace").strip())
            return p.stdout
        return _rsa_chunks(data, ksize, scheme, encrypt, one)
    finally:
        os.unlink(keyfile)


def _openssl_key_size(keyfile, is_public):
    cmd = ["openssl", "rsa", "-in", keyfile, "-noout", "-text"] + (["-pubin"] if is_public else [])
    p = subprocess.run(cmd, capture_output=True, text=True)
    m = re.search(r"(\d+)\s*bit", p.stdout + p.stderr)
    if not m:
        die("cannot read RSA key size from %s" % keyfile)
    return int(m.group(1)) // 8


def _rsa_chunks(data, ksize, scheme, encrypt, one):
    if encrypt:
        step = ksize - SCHEMES[scheme]
        if step <= 0:
            die("RSA key too small for %s" % scheme)
        return b"".join(one(data[i:i + step]) for i in range(0, len(data), step) or [0])
    if len(data) % ksize:
        die("ciphertext is %d bytes, not a multiple of the %d-byte RSA block — wrong key or wrong "
            "outer encoding" % (len(data), ksize))
    return b"".join(one(data[i:i + ksize]) for i in range(0, len(data), ksize))


# ---------------------------------------------------------------------------
# OpenSSL "Salted__" structure
# ---------------------------------------------------------------------------

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int, digest: str):
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        h = hashlib.new(digest)
        h.update(prev + password + salt)
        prev = h.digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def openssl_kdf(args, password: bytes, salt: bytes, key_len: int, iv_len: int):
    if args.kdf == "pbkdf2":
        d = hashlib.pbkdf2_hmac("sha256", password, salt, args.pbkdf2_iter, key_len + iv_len)
        return d[:key_len], d[key_len:key_len + iv_len]
    return evp_bytes_to_key(password, salt, key_len, iv_len, "md5" if args.kdf == "evp-md5" else "sha256")


# ---------------------------------------------------------------------------
# JWE compact
# ---------------------------------------------------------------------------
JWE_ENC = {
    "A128GCM": ("GCM", 16), "A192GCM": ("GCM", 24), "A256GCM": ("GCM", 32),
    "A128CTR": ("CTR", 16), "A192CTR": ("CTR", 24), "A256CTR": ("CTR", 32),
    "A128CBC": ("CBC", 16), "A256CBC": ("CBC", 32),
    "A128CBC-HS256": ("CBC", 16), "A192CBC-HS384": ("CBC", 24), "A256CBC-HS512": ("CBC", 32),
}
JWE_ALG = {"RSA-OAEP-256": "oaep-sha256", "RSA-OAEP": "oaep-sha1", "RSA1_5": "pkcs1"}


def b64u_dec(s: str) -> bytes:
    # tolerate standard-alphabet, padded, and whitespace-only segments (apps ship all three; a lone
    # space is a common stand-in for "this scheme has no authentication tag")
    s = re.sub(r"\s+", "", s or "")
    if not s:
        return b""
    return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))


# a JOSE-shaped blob (5 dot-separated segments, any of which may be empty) inside a bigger body
JOSE_IN_TEXT = re.compile(r"[A-Za-z0-9+/=_-]{8,}\.[A-Za-z0-9+/=_-]*\.[A-Za-z0-9+/=_-]{8,}"
                          r"\.[A-Za-z0-9+/=_-]{8,}\.[A-Za-z0-9+/=_-]*")


def extract_jose(text: str) -> str:
    """Accept a bare token, a quoted string, {"data":"<token>"}, or a whole raw HTTP message.

    Candidates from the regex come first: a wrapper like {"data": "hdr..iv.ct. "} also splits into
    five dot-segments, so trusting the split alone would hand the wrapper back as the "header".
    """
    t = text.strip()
    candidates = [m.group(0) for m in JOSE_IN_TEXT.finditer(t)] + [t.strip('"')]
    for cand in candidates:
        segs = cand.split(".")
        if len(segs) == 5 and _jose_header_of(segs[0]) is not None:
            return cand
    for cand in candidates:
        if len(cand.split(".")) == 5:
            return cand
    return t.strip('"')


def _jose_header_of(seg: str):
    try:
        h = json.loads(b64u_dec(seg))
        return h if isinstance(h, dict) and ("alg" in h or "enc" in h) else None
    except Exception:
        return None


def b64u_enc(b: bytes, padded: bool = False, standard: bool = False) -> str:
    out = (base64.b64encode if standard else base64.urlsafe_b64encode)(b).decode()
    return out if padded else out.rstrip("=")


def jwe_decrypt(token: str, args) -> bytes:
    token = extract_jose(token)
    parts = token.strip().split(".")
    if len(parts) != 5:
        die("not a JWE compact token: %d segments (expected 5)" % len(parts))
    header_seg, ekey_seg, iv_seg, ct_seg, tag_seg = parts
    try:
        hdr = json.loads(b64u_dec(header_seg))
    except Exception:
        hdr = {}
    mode, keylen = _jwe_mode(hdr, args)
    cek = _jwe_cek(ekey_seg, hdr, args, keylen)
    iv, ct, tag = b64u_dec(iv_seg), b64u_dec(ct_seg), b64u_dec(tag_seg)
    aad = header_seg.encode("ascii")
    if args.jwe_state:
        _save_state(args.jwe_state, {"header": header_seg, "encrypted_key": ekey_seg, "tag": tag_seg,
                                     "alg": hdr.get("alg"), "enc": hdr.get("enc"),
                                     "cek": base64.b64encode(cek).decode(),
                                     "standard_b64": bool(re.search(r"[+/]", iv_seg + ct_seg)),
                                     "padded_b64": "=" in (iv_seg + ct_seg + tag_seg)})
    if mode == "GCM":
        pt = aes_transform(cek, iv, ct + tag, "GCM", False, aad=aad, tag_bits=len(tag) * 8 or 128)
    else:
        pt = aes_transform(cek, iv, ct, mode, False)
        if mode == "CBC":
            pt = pkcs7_unpad(pt, strict=args.padding != "none")
    return pt


def jwe_encrypt(plaintext: bytes, args) -> str:
    st = _load_state(args.jwe_state) if args.jwe_state else {}
    header_seg = args.jwe_header or st.get("header")
    ekey_seg = args.jwe_encrypted_key if args.jwe_encrypted_key is not None else st.get("encrypted_key", "")
    if not header_seg:
        die("JWE re-encryption needs the original protected header: decrypt a captured token first with "
            "--jwe-state FILE, or pass --jwe-header")
    try:
        hdr = json.loads(b64u_dec(header_seg))
    except Exception:
        hdr = {}
    mode, keylen = _jwe_mode(hdr, args)
    cek = _jwe_cek(ekey_seg, hdr, args, keylen, state=st)
    iv = load_material(args.iv) if args.iv else os.urandom(12 if mode == "GCM" else 16)
    aad = header_seg.encode("ascii")
    standard = bool(st.get("standard_b64"))
    padded = bool(st.get("padded_b64"))
    if mode == "GCM":
        out = aes_transform(cek, iv, plaintext, "GCM", True, aad=aad, tag_bits=args.tag_length)
        tl = args.tag_length // 8
        ct, tag_seg = out[:-tl], b64u_enc(out[-tl:], padded, standard)
    else:
        data = pkcs7_pad(plaintext) if mode == "CBC" and args.padding != "none" else plaintext
        ct = aes_transform(cek, iv, data, mode, True)
        # non-AEAD content encryption: the original tag segment is not recomputable here — reuse it
        tag_seg = args.jwe_tag if args.jwe_tag is not None else st.get("tag", "")
    return ".".join([header_seg, ekey_seg, b64u_enc(iv, padded, standard),
                     b64u_enc(ct, padded, standard), tag_seg])


def enc_to_mode(enc):
    """'A256GCM' -> 'GCM', tolerating non-standard values like 'A256CTR'."""
    if not enc:
        return None
    e = str(enc).upper()
    if e in JWE_ENC:
        return JWE_ENC[e][0]
    m = re.fullmatch(r"A(?:128|192|256)(GCM|CTR|CBC|CFB|OFB)(?:-HS\d+)?", e)
    return m.group(1) if m else None


def _jwe_mode(hdr, args):
    if args.mode_explicit:
        return args.mode, {16: 16, 24: 24, 32: 32}.get(0, 32)
    enc = (hdr.get("enc") or "").upper()
    if enc in JWE_ENC:
        return JWE_ENC[enc]
    m = re.fullmatch(r"A(128|192|256)(GCM|CTR|CBC|CFB|OFB)", enc)
    if m:
        return m.group(2), int(m.group(1)) // 8
    note("unknown JWE enc %r — assuming %s; override with --mode" % (enc, args.mode))
    return args.mode, 32


def _jwe_cek(ekey_seg, hdr, args, keylen, state=None):
    if args.cek:
        return load_material(args.cek)
    if args.key or args.key_log:      # the content key is known directly (captured, or from a key log)
        return _require_key(args)
    if state and state.get("cek"):
        return base64.b64decode(state["cek"])
    if not ekey_seg:
        die("no CEK: pass --cek (captured content key) or --key, or --priv to unwrap the encrypted key")
    if not args.priv:
        die("the JWE carries a wrapped CEK — pass --priv (your RSA private key, after a key swap) or "
            "--cek with the key captured at runtime")
    scheme = JWE_ALG.get((hdr.get("alg") or "").upper(), args.rsa_scheme)
    cek = rsa_op(b64u_dec(ekey_seg), args.priv, scheme, encrypt=False)
    if len(cek) != keylen:
        note("unwrapped CEK is %d bytes, expected %d for %s" % (len(cek), keylen, hdr.get("enc")))
    return cek


def _save_state(path, obj):
    try:
        with open(path, "w") as fh:
            json.dump(obj, fh, indent=2)
    except OSError as exc:
        note("could not write --jwe-state %s: %s" % (path, exc))


def _load_state(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# top-level structures
# ---------------------------------------------------------------------------

def do_decrypt(payload: str, args) -> bytes:
    if args.engine == "rsa":
        return rsa_op(dec_outer(payload, args.in_encoding), args.priv, args.rsa_scheme, encrypt=False)
    if args.structure == "jwe":
        return jwe_decrypt(payload, args)

    raw = dec_outer(payload, args.in_encoding)
    key = _require_key(args)

    if args.structure == "openssl":
        if raw[:8] != b"Salted__":
            die("structure=openssl but the payload does not start with 'Salted__'")
        salt, ct = raw[8:16], raw[16:]
        klen = args.key_length or len(key) if args.key_length else 32
        k, iv = openssl_kdf(args, key, salt, klen, 0 if args.mode == "ECB" else BLOCK)
        pt = aes_transform(k, iv, ct, args.mode, False, cfb_segment=args.cfb_segment)
        return _unpad(pt, args)

    iv = b""
    ct = raw
    tag = b""
    if args.structure == "iv_ct":
        ivlen = args.iv_length or (12 if args.mode == "GCM" else BLOCK)
        iv, ct = raw[:ivlen], raw[ivlen:]
    elif args.structure == "iv_ct_tag":
        ivlen = args.iv_length or (12 if args.mode == "GCM" else BLOCK)
        tl = args.tag_length // 8
        iv, ct, tag = raw[:ivlen], raw[ivlen:len(raw) - tl], raw[len(raw) - tl:]
    else:                                             # raw
        if args.mode not in ("ECB",):
            iv = load_material(args.iv) if args.iv else b"\x00" * BLOCK
            if not args.iv:
                note("structure=raw and no --iv: assuming an all-zero IV")
    if args.mode == "GCM":
        pt = aes_transform(key, iv, ct + tag, "GCM", False, tag_bits=(len(tag) * 8) or args.tag_length)
        return pt
    pt = aes_transform(key, iv, ct, args.mode, False, cfb_segment=args.cfb_segment)
    return _unpad(pt, args)


def do_encrypt(plaintext: bytes, args) -> str:
    if args.engine == "rsa":
        return enc_outer(rsa_op(plaintext, args.pub or args.priv, args.rsa_scheme, encrypt=True),
                         args.out_encoding)
    if args.structure == "jwe":
        return jwe_encrypt(plaintext, args)

    key = _require_key(args)

    if args.structure == "openssl":
        salt = os.urandom(8)
        klen = args.key_length or 32
        k, iv = openssl_kdf(args, key, salt, klen, 0 if args.mode == "ECB" else BLOCK)
        ct = aes_transform(k, iv, _pad(plaintext, args), args.mode, True, cfb_segment=args.cfb_segment)
        return enc_outer(b"Salted__" + salt + ct, args.out_encoding)

    ivlen = args.iv_length or (12 if args.mode == "GCM" else BLOCK)
    if args.iv:
        iv = load_material(args.iv)
    elif args.structure == "raw" and args.mode != "ECB":
        iv = b"\x00" * BLOCK
        note("structure=raw and no --iv: encrypting with an all-zero IV")
    else:
        iv = os.urandom(ivlen)
    if args.mode == "GCM":
        out = aes_transform(key, iv, plaintext, "GCM", True, tag_bits=args.tag_length)
        tl = args.tag_length // 8
        ct, tag = out[:-tl], out[-tl:]
    else:
        ct = aes_transform(key, iv, _pad(plaintext, args), args.mode, True, cfb_segment=args.cfb_segment)
        tag = b""
    if args.structure == "iv_ct":
        blob = iv + ct + tag
    elif args.structure == "iv_ct_tag":
        blob = iv + ct + tag
    else:
        blob = ct + tag
    return enc_outer(blob, args.out_encoding)


def _first_key(args):
    return args.key[0] if isinstance(args.key, list) else args.key


def _require_key(args):
    if args.key:
        return load_material(_first_key(args))
    if args.key_log:
        entry = resolve_keylog(args, getattr(args, "_payload_text", "") or "")
        return load_material(("%s:%s" % (args.key_log_format, entry["key"]))
                             if args.key_log_format != "auto" else entry["key"])
    die("no key: pass --key (hex:… / b64:… / utf8:… / file:/path / env:NAME / cmd:'…') "
        "or --key-log FILE [--session SID]")


# ---------------------------------------------------------------------------
# post-processing: compression inside the plaintext, and silent-failure detection
# ---------------------------------------------------------------------------

def maybe_inflate(pt: bytes, args) -> bytes:
    """Some apps deflate the JSON before encrypting it — usually as {"data":"<b64(deflate(json))>"}."""
    if args.no_inflate:
        return pt
    import zlib
    for cand in _compressed_candidates(pt):
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
            try:
                out = zlib.decompress(cand, wbits)
            except zlib.error:
                continue
            if out:
                note("plaintext was compressed (zlib) — inflated %d → %d bytes" % (len(cand), len(out)))
                return out
    return pt


def _compressed_candidates(pt: bytes):
    if pt[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        yield pt
    text = pt.decode("utf-8", "replace").strip()
    m = re.fullmatch(r'\{\s*"[A-Za-z0-9_]+"\s*:\s*"([A-Za-z0-9+/=_-]{16,})"\s*\}', text)
    if m:
        raw = _try_b64_bytes(m.group(1))
        if raw:
            yield raw
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", text):
        raw = _try_b64_bytes(text)
        if raw:
            yield raw


def _try_b64_bytes(s: str):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
    return None


def deflate(pt: bytes, wrap: str) -> bytes:
    import zlib
    blob = base64.b64encode(zlib.compress(pt)).decode()
    return ('{"%s":"%s"}' % (wrap, blob)).encode() if wrap else blob.encode()


def sanity_check(pt: bytes):
    """Stream modes (CTR/CFB/OFB) and NoPadding never fail loudly — a wrong key just yields noise."""
    if not pt:
        note("decryption produced 0 bytes — wrong structure, or an empty ciphertext segment")
        return
    printable = sum(1 for b in pt if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if printable / len(pt) < 0.9:
        note("output does not look like text (%d%% printable) — most likely the WRONG KEY. With a key "
             "log, the usual cause is key renewal: run `keys --session <sid>` and pick the key whose "
             "timestamp precedes this request." % int(100 * printable / len(pt)))


def _pad(pt, args):
    return pkcs7_pad(pt) if args.mode in ("CBC", "ECB") and args.padding != "none" else pt


def _unpad(pt, args):
    return pkcs7_unpad(pt, strict=True) if args.mode in ("CBC", "ECB") and args.padding != "none" else pt


# ---------------------------------------------------------------------------
# solve: search the parameter space instead of guessing one combination at a time
# ---------------------------------------------------------------------------

def _complete(pt: bytes) -> bool:
    """Whole-message plaintext, not a fragment: parses as JSON/XML/form or reads as full text."""
    text = pt.decode("utf-8", "replace").strip()
    try:
        json.loads(text)
        return True
    except ValueError:
        pass
    if text[:1] in "{[<" and text[-1:] in "}]>":
        return True
    return not (text[:1] not in "{[<\"" and text[-1:] in "}]>")


def truncation_note(pt: bytes, label: str):
    """The signature of a misread layout: the plaintext is missing exactly its first block."""
    if _complete(pt):
        return None
    if "mode=CBC" not in label:
        return None
    if "structure=iv_ct" in label:
        return ("the output is missing its beginning — one whole block is gone, so those leading 16 "
                "bytes are NOT an IV. The KEY IS RIGHT; the IV lives somewhere else (a hardcoded "
                "literal, the first 16 bytes of the key, a constant in the code). Re-run with "
                "`--structure raw --iv <spec>` once you find it — and note you can already read "
                "everything after the first block.")
    return ("the output is missing its beginning — with CBC that means the IV is wrong while the key "
            "is right. Find the IV the app uses and pass it with --iv.")


def plaintext_score(pt: bytes, expect: str = None) -> float:
    if not pt:
        return 0.0
    if expect and expect.encode() in pt:
        return 2.0
    printable = sum(1 for b in pt if 0x20 <= b < 0x7F or b in (9, 10, 13)) / len(pt)
    if printable < 0.85:
        return printable
    s = printable
    text = pt.decode("utf-8", "replace").strip()
    try:
        json.loads(text)
        s += 0.6
    except ValueError:
        if text[:1] in "{[<" or text[-1:] in "}]>":
            s += 0.25
        if '":"' in text or '": "' in text or "=" in text:
            s += 0.1
    if re.search(r"(?i)\b(?:true|false|null|id|name|user|cpf|token|amount|status|data)\b", text):
        s += 0.1
    return s


def solve(args) -> int:
    """Try every plausible (encoding × structure × mode × IV × key × key-format) and rank by output."""
    global QUIET, SOLVING
    QUIET = SOLVING = True
    payload = args._payload_text.strip()

    key_specs = list(args.key or [])
    if args.key_log:
        key_specs += [k["key"] for k in load_keylog(args.key_log)
                      if not args.session or k["session"].lower() == args.session.lower()]
    if args.key_candidates:
        with open(args.key_candidates) as fh:
            key_specs += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    jose_wrapped = (len(extract_jose(payload).split(".")) == 5
                    and bool(extract_jose(payload).split(".")[1].strip()))
    if not key_specs and not (args.priv and jose_wrapped):
        if args.key_candidates:
            # an empty candidate list is itself a result: the artifact ships no key material
            print("The candidate list is empty — the artifact ships no key-shaped literal, which is a "
                  "finding in itself: this key is almost certainly NEGOTIATED, not shipped.\n"
                  "Go to rung 2: read the first requests of a fresh session, find the key exchange, and "
                  "substitute your own public key in it (references/key-exchange-mitm.md). Then re-run "
                  "with --key-log/--priv.")
            return 1
        die("solve needs candidate keys: --key (repeatable), --key-log, or --key-candidates FILE "
            "(or --priv, for a JOSE token whose key is wrapped)")

    # a key literal means different bytes per interpretation — try each unless one was forced
    keys = []
    for spec in key_specs:
        if re.match(r"(?i)(hex|b64|b64u|base64|base64url|utf8|raw|file|env|cmd):", spec):
            try:
                keys.append((spec, load_material(spec)))
            except (SystemExit, Exception):
                continue
        else:
            for fmt in ("utf8", "hex", "b64"):
                try:
                    kb = load_material("%s:%s" % (fmt, spec))
                except (SystemExit, Exception):
                    continue
                if kb:
                    keys.append(("%s:%s" % (fmt, spec), kb))
    if not keys and not (args.priv and jose_wrapped):
        SOLVING = False
        die("no candidate key could be decoded at all")
    aes_keys = [(sp, k) for sp, k in keys if len(k) in (16, 24, 32)]

    jose = len(extract_jose(payload).split(".")) == 5
    results, partial = [], []
    tried = 0

    def attempt(label, fn, kspec):
        nonlocal tried
        if tried >= args.max_attempts:
            return
        tried += 1
        try:
            pt = fn()
        except (SystemExit, Exception):
            return
        if not pt:
            return
        pt = maybe_inflate(pt, args)
        sc = plaintext_score(pt, args.expect)
        if sc >= 0.85:
            results.append((_complete(pt), sc, label, kspec, pt))
            return
        # right key, wrong IV: with CBC only the FIRST block is garbage
        if "mode=CBC" in label and len(pt) > 2 * BLOCK:
            tail = plaintext_score(pt[BLOCK:], args.expect)
            if tail >= 1.0:
                partial.append((tail, label, kspec, pt))

    if jose:
        token = extract_jose(payload)
        segs = token.split(".")
        iv, ct, tag = b64u_dec(segs[2]), b64u_dec(segs[3]), b64u_dec(segs[4])
        hdr = _jose_header_of(segs[0]) or {}
        if segs[1].strip() and args.priv:      # unwrap the CEK with our (swapped-in) private key
            for scheme in ([JWE_ALG.get((hdr.get("alg") or "").upper())] or []) + \
                          ["oaep-sha256", "oaep-sha1", "pkcs1"]:
                if not scheme:
                    continue
                try:
                    cek = rsa_op(b64u_dec(segs[1]), args.priv, scheme, encrypt=False)
                except (SystemExit, Exception):
                    continue
                if len(cek) in (16, 24, 32):
                    aes_keys.insert(0, ("(CEK unwrapped with --priv, %s)" % scheme, cek))
                    break
        modes = _prune_modes(len(ct), None)
        pref = enc_to_mode(hdr.get("enc"))
        if pref:
            modes = [pref] + [m for m in modes if m != pref]
        for kspec, kb in aes_keys:
            for mode in modes:
                for pad in (True, False):
                    def run(kb=kb, mode=mode, pad=pad):
                        data = ct + tag if mode == "GCM" else ct
                        out = aes_transform(kb, iv, data, mode, False, aad=segs[0].encode(),
                                            tag_bits=(len(tag) * 8) or 128)
                        return pkcs7_unpad(out, strict=False) if (pad and mode in ("CBC", "ECB")) else out
                    attempt("structure=jwe mode=%s%s" % (mode, " (unpad)" if pad else ""), run, kspec)
    else:
        encodings = _encoding_candidates(
            payload, args.encoding if getattr(args, "encoding_explicit", False) else None)
        for enc_name, raw in encodings:
            for structure in ("iv_ct", "raw", "iv_ct_tag", "openssl"):
                if structure == "openssl" and raw[:8] != b"Salted__":
                    continue
                if structure == "iv_ct" and len(raw) <= BLOCK:
                    continue                    # nothing would be left as ciphertext
                if structure == "iv_ct_tag" and len(raw) <= BLOCK + 16:
                    continue
                # an OpenSSL-enc payload is keyed by a *password* of any length; everything else
                # needs a real 16/24/32-byte key
                cand_keys = keys if structure == "openssl" else aes_keys
                kdfs = ("evp-md5", "evp-sha256", "pbkdf2") if structure == "openssl" else (args.kdf,)
                for mode in _prune_modes(len(raw), structure):
                    for kspec, kb in cand_keys:
                        for kdf in kdfs:
                            for iv_label, iv in _iv_candidates(kb, raw, structure, mode, args):
                                for pad in (True, False):
                                    def run(kb=kb, raw=raw, structure=structure, mode=mode, iv=iv,
                                            pad=pad, kdf=kdf):
                                        return _solve_one(kb, raw, structure, mode, iv, pad, args, kdf)
                                    attempt("encoding=%s structure=%s mode=%s iv=%s%s%s"
                                            % (enc_name, structure, mode, iv_label,
                                               " kdf=%s" % kdf if structure == "openssl" else "",
                                               " (unpad)" if pad else ""), run, kspec)

    results.sort(key=lambda r: (not r[0], -r[1]))     # complete plaintexts first
    partial.sort(key=lambda r: -r[0])
    if not results and partial:
        sc, label, kspec, pt = partial[0]
        print("# solve — no exact hit, but a **right key / wrong IV** match (%d attempts)\n" % tried)
        print("key: `%s`" % kspec)
        print("params: %s" % label)
        print("plaintext from the 2nd block on: %s" % pt[BLOCK:BLOCK + 200].decode("utf-8", "replace"))
        print("")
        print("With CBC, exactly one garbled block at the front means the key is right and the IV is "
              "wrong — and that the IV is **not** in the payload. Find the IV literal next to the key "
              "in the code (a hardcoded string, the first 16 bytes of the key, or a constant the app "
              "shares), then:")
        print("  crypto-cli.py dec %s --key '%s' --iv <spec> --in-file <file>"
              % (_repro_args(label), kspec))
        print("")
        print("(Everything after the first block already decrypts, so you can read the traffic now and "
              "fix the IV before you need to *send* anything.)")
        return 0
    if not results and jose and segs[1].strip() and not args.priv:
        print("No hit — and this token carries a WRAPPED KEY in segment 2, so the content key is not "
              "among your candidates by design.\nUnwrap it: swap the app's public key for yours in the "
              "key exchange, then re-run with `--priv file:yours.pem` (see key-exchange-mitm.md), or "
              "capture the CEK where the app sets it.")
        return 1
    if not results:
        print("No combination produced text-like plaintext (%d attempts).\n"
              "Either no candidate key is right, or the scheme has a step this sweep doesn't model "
              "(an extra wrapping layer, a bespoke KDF, a nonce from elsewhere, a per-request key). "
              "Re-read the encrypt path in the app — `static-key-hunt.md`." % tried)
        return 1
    print("# solve — %d hit(s) from %d attempts\n" % (len(results), tried))
    seen = set()
    for complete, sc, label, kspec, pt in results[: args.top]:
        if (label, kspec) in seen:
            continue
        seen.add((label, kspec))
        print("## score %.2f%s — %s" % (sc, "" if complete else " (partial)", label))
        print("key: `%s`" % kspec)
        print("plaintext: %s" % (pt[:300].decode("utf-8", "replace")))
        key_arg = ("--priv %s" % args.priv) if kspec.startswith("(CEK unwrapped") else "--key '%s'" % kspec
        print("reproduce: crypto-cli.py dec %s %s --in-file <file>" % (_repro_args(label), key_arg))
        note_text = truncation_note(pt, label)
        if note_text:
            print("**%s**" % note_text)
        print("")
    print("Confirm the winner on a *different* captured sample before trusting it.")
    return 0


def _solve_one(kb, raw, structure, mode, iv, pad, args, kdf=None):
    if structure == "openssl":
        salt, ct = raw[8:16], raw[16:]
        saved, args.kdf = args.kdf, (kdf or args.kdf)
        try:
            k, iv2 = openssl_kdf(args, kb, salt, 32, 0 if mode == "ECB" else BLOCK)
        finally:
            args.kdf = saved
        out = aes_transform(k, iv2, ct, mode, False)
    elif structure == "iv_ct":
        ivlen = 12 if mode == "GCM" else BLOCK
        out = aes_transform(kb, raw[:ivlen], raw[ivlen:], mode, False,
                            tag_bits=128)
    elif structure == "iv_ct_tag":
        ivlen = 12 if mode == "GCM" else BLOCK
        out = aes_transform(kb, raw[:ivlen], raw[ivlen:], mode, False, tag_bits=128)
    else:
        out = aes_transform(kb, iv, raw, mode, False, tag_bits=128)
    return pkcs7_unpad(out, strict=False) if (pad and mode in ("CBC", "ECB")) else out


def _encoding_candidates(payload: str, forced: str = None):
    """Every outer encoding the payload plausibly is, decoded candidates first."""
    out, seen = [], set()
    for enc in ([forced] if forced else ["base64", "base64url", "hex", "raw"]):
        try:
            raw = dec_outer(payload, enc)
        except Exception:
            continue
        if len(raw) >= 4 and raw not in seen:
            seen.add(raw)
            out.append((enc, raw))
    return out or [("raw", payload.encode("latin-1", "replace"))]


def _gcm_available() -> bool:
    return backend() in ("pycryptodome", "cryptography")


def _prune_modes(length: int, structure):
    """Length arithmetic rules most modes out — try the plausible ones first."""
    block = length % BLOCK == 0
    if structure in ("iv_ct", "iv_ct_tag"):
        block = (length - BLOCK) % BLOCK == 0
    modes = (["CBC", "ECB", "CTR", "CFB", "OFB", "GCM"] if block
             else ["CTR", "GCM", "CFB", "OFB", "CBC"])
    if not _gcm_available():
        modes = [m for m in modes if m != "GCM"]
    return modes


def _iv_candidates(kb, raw, structure, mode, args):
    if structure != "raw" or mode == "ECB":
        return [("(in payload)", b"")]
    out = [("zeros", b"\x00" * BLOCK), ("first16(key)", kb[:BLOCK])]
    if len(kb) == BLOCK:
        out.append(("key", kb))
    if args.iv:
        try:
            out.insert(0, ("--iv", load_material(args.iv)))
        except (SystemExit, Exception):
            pass
    return out


def _repro_args(label: str) -> str:
    parts = []
    for token in label.replace(" (unpad)", "").split():
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        if k == "encoding":
            parts.append("--encoding %s" % v)
        elif k == "structure":
            parts.append("--structure %s" % v)
        elif k == "mode":
            parts.append("--mode %s" % v)
        elif k == "kdf":
            parts.append("--kdf %s" % v)
        elif k == "iv" and v not in ("(in", "(in payload)"):
            parts.append("# iv=%s" % v)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# derive / keygen: ECDH(+HKDF) shared keys, and keypairs for a key swap
# ---------------------------------------------------------------------------

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int, digest: str = "sha256") -> bytes:
    """RFC 5869, stdlib only."""
    import hmac
    hashlen = hashlib.new(digest).digest_size
    prk = hmac.new(salt or b"\x00" * hashlen, ikm, digest).digest()
    okm, t = b"", b""
    for i in range(1, -(-length // hashlen) + 1):
        t = hmac.new(prk, t + info + bytes([i]), digest).digest()
        okm += t
    return okm[:length]


def ecdh_shared(priv_spec: str, peer_spec: str) -> bytes:
    """X25519 / X448 / NIST-curve ECDH via `cryptography`, else the openssl CLI."""
    priv_pem = load_material(priv_spec, want="text")
    peer_pem = load_material(peer_spec, want="text")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec
        k = serialization.load_pem_private_key(priv_pem, password=None)
        peer = serialization.load_pem_public_key(peer_pem)
        if isinstance(k, x25519.X25519PrivateKey) or isinstance(k, x448.X448PrivateKey):
            return k.exchange(peer)
        return k.exchange(ec.ECDH(), peer)
    except ImportError:
        pass
    if not _which("openssl"):
        die("ECDH needs the `cryptography` package or openssl on PATH")
    with tempfile.TemporaryDirectory() as d:
        pv, pb = os.path.join(d, "priv.pem"), os.path.join(d, "peer.pem")
        open(pv, "wb").write(priv_pem)
        open(pb, "wb").write(peer_pem)
        p = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", pv, "-peerkey", pb],
                           capture_output=True)
        if p.returncode:
            die("openssl pkeyutl -derive failed: %s" % p.stderr.decode("utf-8", "replace").strip())
        return p.stdout


def do_derive(args) -> int:
    secret = ecdh_shared(args.priv, args.peer_pub)
    out = secret
    if args.hkdf:
        salt = load_material(args.hkdf_salt) if args.hkdf_salt else b""
        info = load_material(args.hkdf_info) if args.hkdf_info else b""
        out = hkdf(secret, salt, info, args.length or 32, args.hkdf)
        note("HKDF-%s over a %d-byte shared secret → %d bytes" % (args.hkdf, len(secret), len(out)))
    elif args.length and args.length != len(secret):
        note("raw shared secret is %d bytes; truncating to %d (add --hkdf sha256 if the app derives)"
             % (len(secret), args.length))
        out = out[: args.length]
    print(out.hex() if args.out_format == "hex" else
          base64.b64encode(out).decode() if args.out_format == "b64" else out.decode("latin-1"),
          end="" if args.out_format == "raw" else "\n")
    return 0


def do_keygen(args) -> int:
    """Mint the keypair you will substitute into the app's key exchange."""
    if not _which("openssl"):
        die("keygen needs openssl on PATH")
    priv = args.out or "mitm-priv.pem"
    pub = re.sub(r"(-priv)?\.pem$", "", priv) + "-pub.pem"
    if args.alg == "rsa":
        cmd = ["openssl", "genrsa", "-out", priv, str(args.bits)]
    elif args.alg == "x25519":
        cmd = ["openssl", "genpkey", "-algorithm", "X25519", "-out", priv]
    elif args.alg == "p256":
        cmd = ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv]
    else:
        die("unknown --alg %s" % args.alg)
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode:
        die("keygen failed: %s" % p.stderr.decode("utf-8", "replace").strip())
    pubcmd = (["openssl", "rsa", "-in", priv, "-pubout", "-out", pub] if args.alg == "rsa"
              else ["openssl", "pkey", "-in", priv, "-pubout", "-out", pub])
    subprocess.run(pubcmd, capture_output=True)
    print("private: %s\npublic : %s" % (priv, pub))
    print("\nSubstitute the public key into the app's key exchange (or into the artifact), keep the "
          "app's original public key for the outbound leg, and decrypt with the private one.")
    return 0


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def selftest() -> int:
    import types
    ok = fail = 0

    def A(**kw):
        d = dict(engine="aes", mode="CBC", mode_explicit=True, structure="iv_ct", padding="pkcs7",
                 in_encoding="base64", out_encoding="base64", iv=None, iv_length=None, tag_length=128,
                 cfb_segment=128, key=None, cek=None, priv=None, pub=None, rsa_scheme="oaep-sha256",
                 kdf="evp-md5", pbkdf2_iter=10000, key_length=None, jwe_state=None, jwe_header=None,
                 jwe_encrypted_key=None, jwe_tag=None, key_log=None, session=None,
                 key_log_format="auto", no_inflate=True, deflate=False, deflate_wrap="data",
                 quiet=False, session_regex=None, key_candidates=None, expect=None,
                 max_attempts=4000, top=5)
        d.update(kw)
        return types.SimpleNamespace(**d)

    print("backend: %s" % backend())
    key = os.urandom(32)
    kspec = "hex:" + key.hex()
    pt = b'{"cpf":"12345678900","amount":1.5}'

    for mode, struct_ in [("CBC", "iv_ct"), ("CTR", "iv_ct"), ("ECB", "raw"), ("CBC", "openssl"),
                          ("GCM", "iv_ct_tag"), ("CFB", "iv_ct"), ("OFB", "iv_ct")]:
        args = A(mode=mode, structure=struct_, key=kspec)
        try:
            ct = do_encrypt(pt, args)
            back = do_decrypt(ct, args)
            assert back == pt, "roundtrip mismatch: %r" % back[:40]
            print("  ok   AES-%s / %s" % (mode, struct_))
            ok += 1
        except SystemExit as exc:
            print("  SKIP AES-%s / %s (%s)" % (mode, struct_, exc.code if exc.code != 2 else "unsupported here"))
        except Exception as exc:
            print("  FAIL AES-%s / %s: %s" % (mode, struct_, exc))
            fail += 1

    # RSA + JWE need a keypair
    if _which("openssl"):
        d = tempfile.mkdtemp()
        priv, pub = os.path.join(d, "p.pem"), os.path.join(d, "P.pem")
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], capture_output=True)
        for scheme in ("oaep-sha256", "oaep-sha1", "pkcs1"):
            args = A(engine="rsa", rsa_scheme=scheme, priv="file:" + priv, pub="file:" + pub)
            try:
                ct = do_encrypt(pt, args)
                back = do_decrypt(ct, args)
                assert back == pt
                print("  ok   RSA %s" % scheme)
                ok += 1
            except SystemExit as exc:
                print("  SKIP RSA %s (%s)" % (scheme, exc.code))
            except Exception as exc:
                print("  FAIL RSA %s: %s" % (scheme, exc))
                fail += 1

        # JWE: build a token the way a hybrid app would, then round-trip it
        for enc, mode in (("A256CTR", "CTR"), ("A256GCM", "GCM")):
            state = os.path.join(d, "jwe-%s.json" % enc)
            try:
                cek = os.urandom(32)
                hdr = b64u_enc(json.dumps({"alg": "RSA-OAEP", "enc": enc}).encode())
                ekey = b64u_enc(rsa_op(cek, "file:" + pub, "oaep-sha1", encrypt=True))
                iv = os.urandom(12 if mode == "GCM" else 16)
                aad = hdr.encode()
                if mode == "GCM":
                    blob = aes_transform(cek, iv, pt, "GCM", True, aad=aad)
                    ct, tag = blob[:-16], blob[-16:]
                else:
                    ct, tag = aes_transform(cek, iv, pt, "CTR", True), b""
                token = ".".join([hdr, ekey, b64u_enc(iv), b64u_enc(ct), b64u_enc(tag)])
                args = A(structure="jwe", mode_explicit=False, mode=mode, priv="file:" + priv,
                         jwe_state=state)
                back = do_decrypt(token, args)
                assert back == pt, "jwe decrypt mismatch"
                token2 = do_encrypt(pt, args)
                assert do_decrypt(token2, args) == pt, "jwe re-encrypt not readable"
                print("  ok   JWE %s (unwrap + re-encrypt via --jwe-state)" % enc)
                ok += 1
            except SystemExit as exc:
                print("  SKIP JWE %s (%s)" % (enc, exc.code))
            except Exception as exc:
                print("  FAIL JWE %s: %s" % (enc, exc))
                fail += 1

    print("\n%d ok, %d failed" % (ok, fail))
    return 1 if fail else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("dec", "enc", "solve", "keys", "derive", "keygen",
                                       "selftest"))

    g = ap.add_argument_group("input / output")
    g.add_argument("--data", help="payload as a string ({DATA} in Re:Encrypt)")
    g.add_argument("--in-file", help="payload from a file ({FILE} in Re:Encrypt — prefer this)")
    g.add_argument("--out-file", help="write the result here instead of stdout")
    g.add_argument("--encoding", choices=ENCODINGS, default="base64",
                   help="outer encoding of the ciphertext on the wire (default base64)")
    g.add_argument("--in-encoding", choices=ENCODINGS, help="override the input side only")
    g.add_argument("--out-encoding", choices=ENCODINGS, help="override the output side only")

    g = ap.add_argument_group("scheme")
    g.add_argument("--engine", choices=("aes", "rsa"), default="aes")
    g.add_argument("--mode", default="CBC", help="AES mode: %s (default CBC)" % "|".join(MODES))
    g.add_argument("--structure", choices=STRUCTURES, default="raw",
                   help="how the pieces are laid out in the payload (default raw)")
    g.add_argument("--padding", choices=("pkcs7", "none"), default="pkcs7")
    g.add_argument("--iv-length", type=int, help="IV bytes for iv_ct / iv_ct_tag (default 16, GCM 12)")
    g.add_argument("--tag-length", type=int, default=128, help="GCM tag bits (default 128)")
    g.add_argument("--cfb-segment", type=int, default=128, choices=(8, 128),
                   help="CFB feedback size; 128 matches Java 'AES/CFB' and openssl aes-*-cfb")

    g = ap.add_argument_group("key material")
    g.add_argument("--key", action="append", help="AES key spec (repeatable: solve tries each)")
    g.add_argument("--key-log", metavar="FILE",
                   help="key log ('<ts>: <key> [<session-id>]' per line) to resolve the key from")
    g.add_argument("--session", metavar="SID",
                   help="pick the newest key of this session from --key-log")
    g.add_argument("--session-regex", metavar="RE",
                   help="how to find the session id in a raw message (group 1), when the default "
                        "name-based search misses it")
    g.add_argument("--key-candidates", metavar="FILE",
                   help="solve: one candidate key literal per line (e.g. from the triage report)")
    g.add_argument("--key-log-format", choices=("auto", "hex", "b64", "b64u", "utf8"), default="auto",
                   help="how to read key-log values (default auto: 32 printable chars = UTF-8 bytes)")
    g.add_argument("--iv", help="IV spec (structure=raw, or to force a fixed IV on encrypt)")
    g.add_argument("--priv", help="RSA private key spec (PEM)")
    g.add_argument("--pub", help="RSA public key spec (PEM)")
    g.add_argument("--rsa-scheme", choices=tuple(SCHEMES), default="oaep-sha256")
    g.add_argument("--cek", help="JWE content encryption key spec (when captured at runtime)")

    g = ap.add_argument_group("structure=openssl (Salted__)")
    g.add_argument("--kdf", choices=("evp-md5", "evp-sha256", "pbkdf2"), default="evp-md5")
    g.add_argument("--pbkdf2-iter", type=int, default=10000)
    g.add_argument("--key-length", type=int, help="derived key bytes (default 32)")

    g = ap.add_argument_group("structure=jwe")
    g.add_argument("--jwe-state", metavar="FILE",
                   help="remember header/wrapped-key/tag/CEK on dec and reuse them on enc")
    g.add_argument("--jwe-header", help="protected header segment (base64url) to re-encrypt under")
    g.add_argument("--jwe-encrypted-key", help="wrapped-key segment to reuse verbatim")
    g.add_argument("--jwe-tag", help="tag segment to reuse verbatim (non-AEAD content encryption)")

    g = ap.add_argument_group("solve (parameter search)")
    g.add_argument("--expect", metavar="STR",
                   help="a string the plaintext must contain (a CPF, a field name) — makes the winner "
                        "unambiguous")
    g.add_argument("--max-attempts", type=int, default=4000, help="cap the sweep (default 4000)")
    g.add_argument("--top", type=int, default=5, help="how many hits to print")

    g = ap.add_argument_group("derive (ECDH + HKDF) / keygen")
    g.add_argument("--peer-pub", help="derive: the other side's public key (PEM)")
    g.add_argument("--hkdf", choices=("sha256", "sha1", "sha384", "sha512"),
                   help="derive: run HKDF over the shared secret (most ECDH schemes do)")
    g.add_argument("--hkdf-salt", help="derive: HKDF salt spec (default empty)")
    g.add_argument("--hkdf-info", help="derive: HKDF info/context spec (default empty)")
    g.add_argument("--length", type=int, help="derive: output key bytes (default 32)")
    g.add_argument("--out-format", choices=("hex", "b64", "raw"), default="hex")
    g.add_argument("--alg", choices=("rsa", "x25519", "p256"), default="rsa", help="keygen algorithm")
    g.add_argument("--bits", type=int, default=2048, help="keygen: RSA size")
    g.add_argument("--out", help="keygen: private key path (public key gets a -pub.pem sibling)")

    g = ap.add_argument_group("plaintext post-processing")
    g.add_argument("--no-inflate", action="store_true",
                   help="don't try to zlib-inflate the decrypted plaintext")
    g.add_argument("--deflate", action="store_true",
                   help="zlib-compress + base64 the plaintext before encrypting (mirror of the above)")
    g.add_argument("--deflate-wrap", metavar="FIELD", default="data",
                   help="JSON field to wrap the compressed blob in, '' for bare (default: data)")
    g.add_argument("-q", "--quiet", action="store_true",
                   help="no diagnostics on stderr — REQUIRED when used as a proxy command, since "
                        "Re:Encrypt merges stderr into the command output")
    return ap


def main(argv=None):
    global QUIET
    ap = build_parser()
    args = ap.parse_args(argv)
    QUIET = QUIET or args.quiet
    if args.action == "selftest":
        return selftest()
    if args.action == "keys":
        if not args.key_log:
            die("keys needs --key-log FILE")
        rows = load_keylog(args.key_log)
        if args.session:
            rows = [r for r in rows if r["session"].lower() == args.session.lower()]
            if not rows:
                die("no key for session %s in %s" % (args.session, args.key_log))
        for r in rows:
            print("%s  %s  %s" % (r["time"], r["key"], r["session"] or "-"))
        print("\n%d key(s)%s — the newest is the last line; an older capture needs the key whose "
              "timestamp precedes it (pass it with --key)."
              % (len(rows), " for session %s" % args.session if args.session else ""), file=sys.stderr)
        return 0

    if args.action == "keygen":
        return do_keygen(args)
    if args.action == "derive":
        if not (args.priv and args.peer_pub):
            die("derive needs --priv (yours) and --peer-pub (theirs)")
        return do_derive(args)

    args.mode = args.mode.upper()
    if args.mode not in MODES:
        die("unsupported --mode %s (use %s)" % (args.mode, "|".join(MODES)))
    _argv = argv if argv is not None else sys.argv[1:]
    args.mode_explicit = any(a.startswith("--mode") for a in _argv)
    # solve must know whether the encoding was *given* or is just the default, or it would sweep one
    args.encoding_explicit = any(a.startswith(("--encoding", "--in-encoding")) for a in _argv)
    args.in_encoding = args.in_encoding or args.encoding
    args.out_encoding = args.out_encoding or args.encoding

    if args.in_file:
        with open(args.in_file, "rb") as fh:
            payload_bytes = fh.read()
    elif args.data is not None:
        payload_bytes = args.data.encode("utf-8")
    else:
        payload_bytes = sys.stdin.buffer.read()

    payload_text = payload_bytes.decode("utf-8", "replace")
    args._payload_text = payload_text          # lets --key-log sniff a session id from a raw message

    if args.action == "solve":
        return solve(args)

    if args.action == "dec":
        out = do_decrypt(payload_text, args)
        blob = out if isinstance(out, bytes) else out.encode("utf-8")
        blob = maybe_inflate(blob, args)
        sanity_check(blob)
    else:
        if args.deflate:
            payload_bytes = deflate(payload_bytes, args.deflate_wrap)
        res = do_encrypt(payload_bytes, args)
        blob = res.encode("utf-8") if isinstance(res, str) else res

    if args.out_file:
        with open(args.out_file, "wb") as fh:
            fh.write(blob)
    else:
        sys.stdout.buffer.write(blob)
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
