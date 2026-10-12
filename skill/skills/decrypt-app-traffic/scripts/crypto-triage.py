#!/usr/bin/env python3
"""
crypto-triage.py — static triage of APK/IPA artifacts for *transport* crypto.

Answers, from the artifact alone and with no external tooling: which crypto APIs the app calls,
which framework/network stack it uses, what key material it ships, and where to look next.
Everything is stdlib-only (zipfile + a builtin binary-XML/DEX/Mach-O reader), so it runs before
jadx/apktool/aapt are installed; when `aapt`/`apkanalyzer` *is* on PATH it is used for identity.

Usage:
  crypto-triage.py APPS_DIR                        # triage every apk/ipa/aab/xapk found
  crypto-triage.py app.apk other.ipa               # explicit artifacts
  crypto-triage.py APPS_DIR --out triage/          # write <name>.triage.{md,json}, .keys.txt, PEMs
  crypto-triage.py app.apk --json                  # machine-readable to stdout
  crypto-triage.py app.apk --grep 'MY_SECRET'      # add ad-hoc indicator patterns (repeatable)

Reading the report: every hit is a **lead**, not a conclusion. A key candidate is a string of the
right shape, not a proven key — prove it by decrypting a real captured sample. With `--out`, the
candidates are also written to `<name>.keys.txt`, which is exactly what
`crypto-cli.py solve --key-candidates <file>` consumes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from collections import OrderedDict

ARTIFACT_EXT = (".apk", ".ipa", ".aab", ".xapk", ".apks")

# Entries worth scanning byte-wise, by extension / path shape.
SCAN_SUFFIXES = (
    ".dex", ".so", ".js", ".jsbundle", ".bundle", ".hbc", ".jsc", ".mjs", ".cjs", ".ts",
    ".json", ".html", ".htm", ".xml", ".plist", ".properties", ".txt", ".pem", ".der",
    ".cer", ".crt", ".key", ".jwk", ".conf", ".cfg", ".yaml", ".yml", ".env", ".dat",
    ".bin", ".jar", ".dll", ".vue", ".map",
)
# Paths that are worth reading whatever their extension: app assets and web roots are where JS
# crypto, keys and config live, and they are frequently extensionless or oddly named.
SCAN_PATHS = ("assets/", "/www/", "res/raw/", "public/", "payload/")
SCAN_PATH_MAX = 48 * 1024 * 1024
MAX_ENTRY_SCAN = 96 * 1024 * 1024   # per-entry cap on decompressed bytes scanned
CHUNK = 4 * 1024 * 1024

# ---------------------------------------------------------------------------
# Indicator table: (category, label, compiled pattern)
# Patterns run over raw bytes of every scanned entry (and over DEX string tables).
# ---------------------------------------------------------------------------
def _ind(cat, label, pat, flags=0):
    return (cat, label, re.compile(pat.encode() if isinstance(pat, str) else pat, flags))


INDICATORS = [
    # --- symmetric transforms: the single most useful hit, it names mode+padding ---
    _ind("cipher", "AES transform string", r"AES/(?:CBC|ECB|CTR|GCM|CFB8?|OFB)/(?:PKCS[57]Padding|NoPadding|ISO10126Padding)"),
    _ind("cipher", "AES transform (short)", r"\bAES/(?:CBC|ECB|CTR|GCM|CFB|OFB)\b"),
    _ind("cipher", "bare AES / DESede", r"\b(?:AES|DESede|DES|Blowfish|ARCFOUR|RC4|ChaCha20(?:-Poly1305)?)\b(?=[^A-Za-z0-9]|$)"),
    _ind("cipher", "RSA transform", r"RSA/(?:ECB|NONE)/(?:PKCS1Padding|OAEPWith[A-Za-z0-9-]+Padding|OAEPPadding|NoPadding)"),
    _ind("cipher", "javax.crypto usage", r"javax/crypto/(?:Cipher|Mac|spec/SecretKeySpec|spec/IvParameterSpec|spec/GCMParameterSpec|KeyGenerator|spec/PBEKeySpec)"),
    _ind("cipher", "SecretKeySpec/IvParameterSpec", r"(?:SecretKeySpec|IvParameterSpec|GCMParameterSpec)"),
    _ind("cipher", "Android Keystore", r"AndroidKeyStore"),
    _ind("cipher", "BouncyCastle / Conscrypt / Tink", r"(?:org/bouncycastle|spongycastle|com/google/crypto/tink|conscrypt)"),
    _ind("cipher", "libsodium / NaCl", r"(?:libsodium|crypto_secretbox|crypto_box_easy|tweetnacl)"),

    # --- key derivation ---
    _ind("kdf", "PBKDF2", r"PBKDF2With(?:Hmac)?(?:SHA1|SHA256|SHA512)|PBKDF2"),
    _ind("kdf", "scrypt / argon2 / bcrypt", r"(?:scrypt|argon2(?:id|i|d)?|bcrypt)"),
    _ind("kdf", "HKDF", r"HKDF(?:-?SHA(?:1|256|512))?"),
    _ind("kdf", "EVP_BytesToKey (OpenSSL enc)", r"(?:EVP_BytesToKey|Salted__)"),

    # --- MAC / signature over the body (breaks tampering if unhandled) ---
    _ind("mac", "HMAC", r"Hmac(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512)"),
    _ind("mac", "signature header name", r"(?i)x-(?:body-)?(?:signature|sign|sig|hmac|digest|checksum)\b"),
    _ind("mac", "nonce/timestamp header", r"(?i)x-(?:nonce|timestamp|request-id|ts)\b"),

    # --- structures / formats seen on the wire ---
    _ind("structure", "JWE/JWS header (b64)", r"eyJ(?:hbGci|lbmMi|0eXAi)"),
    _ind("structure", "JWE alg names", r"(?:RSA-OAEP(?:-256)?|RSA1_5|A128GCM|A256GCM|A128CBC-HS256|A256CTR|dir\b)"),
    _ind("structure", "JOSE library", r"(?:nimbus-jose|com/nimbusds/jose|jose4j|jwcrypto|node-jose|jose\.JWE)"),
    _ind("structure", "PEM public key", r"-----BEGIN (?:RSA )?PUBLIC KEY-----"),
    _ind("structure", "PEM private key", r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----"),
    _ind("structure", "PEM certificate", r"-----BEGIN CERTIFICATE-----"),
    _ind("structure", "JWK", r'"kty"\s*:\s*"(?:RSA|EC|oct)"'),
    _ind("structure", "PKCS12 / keystore file", r"(?:\.p12|\.pfx|\.jks|\.bks|PKCS12|KeyStore\.getInstance)"),

    # --- JS-side crypto (RN / Cordova / WebView apps) ---
    _ind("jscrypto", "CryptoJS", r"CryptoJS(?:\.(?:AES|enc|mode|pad|HmacSHA256))?"),
    _ind("jscrypto", "CryptoJS passphrase form (string key -> OpenSSL envelope, AES-256)",
         r"(?:CryptoJS\.)?AES\.(?:en|de)crypt\s*\([^,)]{1,80},\s*[\"'][^\"']{4,64}[\"']"),
    _ind("jscrypto", "CryptoJS raw-key form (enc.*.parse -> needs an explicit IV)",
         r"(?:CryptoJS\.)?enc\.(?:Utf8|Hex|Base64|Latin1)\.parse\s*\("),
    _ind("jscrypto", "CryptoJS iv/mode options", r"\{\s*iv\s*:|mode\s*:\s*CryptoJS\.mode\.|pad\s*:\s*CryptoJS\.pad\."),
    _ind("structure", "OpenSSL envelope literal (base64 'Salted__')", r"U2FsdGVkX1"),
    _ind("jscrypto", "node-forge", r"(?:node-forge|forge\.pki|forge\.cipher)"),
    _ind("jscrypto", "JSEncrypt", r"JSEncrypt"),
    _ind("jscrypto", "WebCrypto subtle", r"crypto\.subtle\.(?:encrypt|decrypt|importKey|deriveKey)"),
    _ind("jscrypto", "sjcl / jsrsasign", r"(?:sjcl\.|KJUR\.|jsrsasign)"),

    # --- pinning / cleartext posture (predicts the interception work) ---
    _ind("pinning", "OkHttp CertificatePinner", r"(?:CertificatePinner|certificatePinner)"),
    _ind("pinning", "TrustKit / AFNetworking pinning", r"(?:TrustKit|AFSecurityPolicy|SSLPinning)"),
    _ind("pinning", "sha256 pin literal", r"sha256/[A-Za-z0-9+/=]{43,}"),
    _ind("pinning", "network_security_config", r"network_security_config"),

    # --- key exchange / handshake: the key is negotiated, not shipped ---
    _ind("exchange", "RSA keypair generated at runtime", r"(?:generateKeyPair|KeyPairGenerator|forge\.pki\.rsa|rsa\.generateKeyPair|SecKeyCreateRandomKey)"),
    _ind("exchange", "JSEncrypt / client-side RSA", r"(?:JSEncrypt|setPublicKey|setPrivateKey)"),
    _ind("exchange", "handshake endpoint", r"[\"'/](?:init|handshake|keyexchange|key-exchange|exchange|getkey|publickey|pubkey|keys)[\"'/?]"),
    _ind("exchange", "JWK / kid key delivery", r"(?:\"jwk\"|\"kid\"|jwk\.kid)"),
    _ind("exchange", "X25519 / ECDH + HKDF", r"(?:X25519|curve25519|ECDH|generateSharedSecret|HKDF)"),
    _ind("exchange", "key renewal / expiry", r"(?:\"exp\"|renov|renew|expira|refreshKey|rotateKey)"),

    # --- endpoints ---
    _ind("endpoint", "https URL", r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,120}"),
    _ind("endpoint", "http URL (cleartext)", r"http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,120}"),
    _ind("endpoint", "ws URL", r"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,120}"),

    # --- iOS / native crypto symbols ---
    _ind("cipher", "CommonCrypto", r"(?:CCCrypt|CCCryptorCreate(?:WithMode)?|kCCAlgorithmAES|CCHmac)"),
    _ind("cipher", "Security.framework RSA", r"(?:SecKeyCreateEncryptedData|SecKeyCreateDecryptedData|SecKeyEncrypt|SecKeyRawSign|kSecKeyAlgorithmRSAEncryptionOAEP)"),
    _ind("cipher", "OpenSSL/BoringSSL symbols", r"(?:EVP_EncryptInit_ex|EVP_aes_256_(?:cbc|gcm|ctr)|RSA_public_encrypt|BoringSSL)"),
]

# Class/symbol names worth opening first in jadx / a disassembler.
CODE_NAME = re.compile(
    r"(?:L[A-Za-z0-9/_$]{3,120};|\b[A-Za-z0-9_$]{4,60}\b)"
)
CODE_NAME_INTEREST = re.compile(
    r"(?i)(?:crypt|cipher|aes|rsa|jwe|jws|jose|hmac|sign(?:er|ature)?|secure|secret|keystore|"
    r"keymanager|keyprovider|obfusc|protect|payload|envelope)"
)
PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]{2,40})-----[\r\n]+([A-Za-z0-9+/=\s]{40,6000}?)-----END \1-----"
)

# Names that, appearing next to a literal, hint the literal is key material.
KEYISH_NAME = re.compile(
    r"(?i)(?:secret|passphrase|password|passwd|pwd|aes_?key|enc_?key|crypt_?key|master_?key|"
    r"private_?key|pub(?:lic)?_?key|iv|salt|token_?key|hmac_?key|signing_?key|api_?secret)"
)

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def printable(s: bytes) -> str:
    return s.decode("utf-8", "replace").replace("\x00", "")


def clip(s: str, n: int = 160) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Android binary XML (AXML) — string pool + element/attribute walk
# ---------------------------------------------------------------------------
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_ELEMENT = 0x0102
RES_XML_RESOURCE_MAP = 0x0180


def _axml_string_pool(buf: bytes, off: int):
    """Parse a RES_STRING_POOL chunk at off; return list[str]."""
    _type, header_size, chunk_size = struct.unpack_from("<HHI", buf, off)
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", buf, off + 8)
    utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack_from("<%dI" % string_count, buf, off + header_size) if string_count else ()
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                # two varint-ish lengths (chars, bytes); high bit means 2-byte length
                n_chars, p = _u8len(buf, p)
                n_bytes, p = _u8len(buf, p)
                out.append(buf[p:p + n_bytes].decode("utf-8", "replace"))
            else:
                n, p = _u16len(buf, p)
                out.append(buf[p:p + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out, chunk_size


def _u8len(buf, p):
    v = buf[p]
    p += 1
    if v & 0x80:
        v = ((v & 0x7F) << 8) | buf[p]
        p += 1
    return v, p


def _u16len(buf, p):
    v = struct.unpack_from("<H", buf, p)[0]
    p += 2
    if v & 0x8000:
        v = ((v & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
        p += 2
    return v, p


def parse_axml(buf: bytes):
    """Return (elements, strings). elements = [(tag, {attr: value})]. Best-effort."""
    strings: list[str] = []
    elements: list[tuple[str, dict]] = []
    if len(buf) < 8 or struct.unpack_from("<H", buf, 0)[0] != RES_XML:
        return elements, strings

    def s(i):
        return strings[i] if 0 <= i < len(strings) else ""

    off = struct.unpack_from("<H", buf, 2)[0]  # header size of the file chunk
    while off + 8 <= len(buf):
        ctype, _hsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize <= 0 or off + csize > len(buf):
            break
        if ctype == RES_STRING_POOL:
            try:
                strings, _ = _axml_string_pool(buf, off)
            except Exception:
                strings = []
        elif ctype == RES_XML_START_ELEMENT:
            try:
                # node header: line(u32) comment(u32) then ns(u32) name(u32)
                ns_i, name_i = struct.unpack_from("<iI", buf, off + 16)
                attr_start, _attr_size, attr_count = struct.unpack_from("<HHH", buf, off + 24)
                attrs = {}
                # attributeStart is relative to the start of the attrExt struct (off + 16)
                ap = off + 16 + attr_start
                for _ in range(attr_count):
                    a_ns, a_name, a_raw = struct.unpack_from("<iii", buf, ap)
                    d_type, d_data = struct.unpack_from("<BI", buf, ap + 15)
                    if a_raw >= 0:
                        val = s(a_raw)
                    elif d_type == 0x03:
                        val = s(d_data)
                    elif d_type == 0x12:
                        val = "true" if d_data else "false"
                    elif d_type == 0x01:
                        val = "@0x%08x" % d_data
                    else:
                        val = str(d_data)
                    attrs[s(a_name)] = val
                    ap += 20
                elements.append((s(name_i), attrs))
                del ns_i
            except Exception:
                pass
        off += csize
    return elements, strings


def android_manifest_facts(buf: bytes) -> dict:
    els, strings = parse_axml(buf)
    facts: dict = {"package": None, "versionName": None, "flags": {}, "exported": [], "deeplinks": [],
                   "permissions": [], "manifest_parsed": bool(els)}
    cur_component = None
    for tag, attrs in els:
        if tag == "manifest":
            facts["package"] = attrs.get("package") or facts["package"]
            facts["versionName"] = attrs.get("versionName")
        elif tag == "application":
            for k in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig"):
                if k in attrs:
                    facts["flags"][k] = attrs[k]
        elif tag == "uses-permission":
            n = attrs.get("name")
            if n:
                facts["permissions"].append(n)
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            cur_component = attrs.get("name", "?")
            if attrs.get("exported") == "true":
                facts["exported"].append("%s %s" % (tag, cur_component))
        elif tag == "data":
            scheme, host = attrs.get("scheme"), attrs.get("host")
            if scheme and scheme not in ("http", "https") or (scheme and host):
                facts["deeplinks"].append("%s://%s" % (scheme, host or ""))
    if not facts["package"]:
        # fallback: the manifest string pool holds the package as a dotted lowercase token
        cand = [t for t in strings if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,5}", t or "")]
        facts["package"] = cand[0] if cand else None
    facts["deeplinks"] = sorted(set(facts["deeplinks"]))[:20]
    return facts


# ---------------------------------------------------------------------------
# DEX string table
# ---------------------------------------------------------------------------

def dex_strings(buf: bytes, limit: int = 400000):
    """Yield strings from a DEX string_id table (no dependency on dexlib)."""
    if len(buf) < 0x70 or buf[:4] not in (b"dex\n", b"dey\n"):
        return
    try:
        string_ids_size, string_ids_off = struct.unpack_from("<II", buf, 0x38)
    except struct.error:
        return
    n = min(string_ids_size, limit)
    for i in range(n):
        try:
            data_off = struct.unpack_from("<I", buf, string_ids_off + 4 * i)[0]
            p = data_off
            _size, p = _uleb128(buf, p)
            end = buf.index(b"\x00", p)
            yield buf[p:end].decode("utf-8", "replace")
        except Exception:
            continue


def _uleb128(buf, p):
    result = 0
    shift = 0
    while True:
        b = buf[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, p
        shift += 7


# ---------------------------------------------------------------------------
# key-material candidates
# ---------------------------------------------------------------------------
HEX_KEY = re.compile(r"\A(?:[0-9a-fA-F]{2}){16,64}\Z")
B64ISH = re.compile(r"\A[A-Za-z0-9+/]{20,}={0,2}\Z")
B64URLISH = re.compile(r"\A[A-Za-z0-9_-]{20,}\Z")
ASCII_KEY = re.compile(r"\A[\x21-\x7e]{8,64}\Z")
# dotted/dashed identifiers (header names, class names, versions) are never the key value
IDENTIFIERISH = re.compile(r"\A[A-Za-z][A-Za-z0-9]*(?:[.\-_/][A-Za-z0-9]+)+\Z")
CODEISH = re.compile(r"[(){};<>\\]|\A[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]")
# CamelCase / snake_case words: identifiers and resource names, never passphrases
WORDISH = re.compile(r"\A[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]*)*\Z")


def _charclasses(s: str) -> int:
    return sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))


def key_candidates(strings, source: str, out: dict, quoted: bool = False):
    """Rank literals that could be an AES key/IV, a passphrase, or a shared secret.

    `quoted=True` means these came from inside string quotes in source code — already a strong hint
    that they are literals rather than code, so the charset requirement is relaxed (a key like
    "0123456789abcdef" has only two character classes but is exactly what apps ship).
    """
    min_classes = 2 if quoted else 3
    for s in strings:
        if not s or len(s) > 200:
            continue
        why = None
        score = 0
        if HEX_KEY.fullmatch(s) and len(s) // 2 in (16, 24, 32):
            why, score = "hex, decodes to %d bytes" % (len(s) // 2), 90
        elif (B64ISH.fullmatch(s) or B64URLISH.fullmatch(s)):
            raw = _try_b64(s)
            if raw is not None and len(raw) in (16, 24, 32) and shannon(raw) > 3.2:
                why, score = "base64, decodes to %d bytes (entropy %.1f)" % (len(raw), shannon(raw)), 85
        if why is None and ASCII_KEY.fullmatch(s) and len(s) in (16, 24, 32) \
                and not IDENTIFIERISH.fullmatch(s) and not CODEISH.search(s) \
                and _charclasses(s) >= min_classes:
            # a 16/24/32-char ASCII literal is the classic "key as a password" pattern
            why, score = "%d ASCII chars (UTF-8 key of exactly a legal AES size)" % len(s), \
                75 if quoted else 70
        if why is None and quoted and 6 <= len(s) <= 40 and ASCII_KEY.fullmatch(s) \
                and not IDENTIFIERISH.fullmatch(s) and not CODEISH.search(s) \
                and not WORDISH.fullmatch(s) and not re.search(r"[/\\:\s]", s) \
                and _charclasses(s) >= 3 and len(re.findall(r"[^A-Za-z0-9]", s)) >= 2:
            # a password-looking quoted literal of ANY length: key derivation (CryptoJS string key,
            # openssl enc, PBKDF2) accepts any length, so don't filter on 16/24/32 here
            why, score = "%d-char password-like literal — try it as a PASSPHRASE " \
                         "(structure=openssl / a KDF)" % len(s), 55
        if why is None:
            continue
        if KEYISH_NAME.search(s):
            score -= 20  # this looks like the *name*, not the value
            why += " — looks like an identifier, not a value"
        prev = out.get(s)
        if prev is None or score > prev["score"]:
            out[s] = {"value": s, "why": why, "score": score, "sources": {source}}
        else:
            prev["sources"].add(source)


def _try_b64(s: str):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = "=" * (-len(s) % 4)
            return fn(s + pad)
        except (binascii.Error, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# framework / stack detection
# ---------------------------------------------------------------------------

def detect_stack(names) -> list[str]:
    stack = []
    joined = "\n".join(names)

    def has(pat):
        return re.search(pat, joined) is not None

    if has(r"assets/index\.android\.bundle") or has(r"\.jsbundle"):
        stack.append("React Native (JS bundle — grep it for the crypto; Hermes bytecode needs hermes-dec)")
    if has(r"lib/[^/\n]+/libflutter\.so"):
        stack.append("Flutter (Dart; use reFlutter/blutter — its crypto and HTTP client are inside libapp.so)")
    if has(r"assets/www/|public/cordova\.js|capacitor\.config"):
        stack.append("Cordova/Capacitor (WebView — the crypto is in assets/www JS)")
    if has(r"lib/[^/\n]+/libil2cpp\.so|assets/bin/Data"):
        stack.append("Unity/IL2CPP (global-metadata.dat + libil2cpp.so)")
    if has(r"assemblies/.*\.dll|\.net\.dll"):
        stack.append("Xamarin/MAUI (.NET assemblies — decompile with ilspycmd)")
    if has(r"lib/[^/\n]+/libcronet"):
        stack.append("Cronet HTTP stack (pinning/proxy behave differently from OkHttp)")
    if has(r"okhttp3?/|okhttp"):
        stack.append("OkHttp")
    if has(r"Payload/[^/\n]+\.app/Frameworks/Flutter\.framework"):
        stack.append("Flutter (iOS)")
    if not stack:
        stack.append("native (Java/Kotlin or Swift/ObjC) — no cross-platform runtime detected")
    return stack


# ---------------------------------------------------------------------------
# per-artifact triage
# ---------------------------------------------------------------------------

def triage(path: str, extra_patterns, verbose=False) -> dict:
    rep: dict = {
        "artifact": os.path.abspath(path),
        "size": os.path.getsize(path),
        "sha256": sha256_file(path),
        "platform": None, "identity": {}, "stack": [], "entries": 0,
        "hits": OrderedDict(), "key_candidates": [], "pem": [], "endpoints": [],
        "code_names": [], "next_steps": [], "warnings": [],
    }
    cand: dict = {}
    hits: dict = {}
    pems: dict = {}
    code: dict = {}

    def add_hit(cat, label, sample, where):
        k = (cat, label)
        h = hits.setdefault(k, {"category": cat, "label": label, "count": 0, "samples": [], "where": {}})
        h["count"] += 1
        h["where"][where] = h["where"].get(where, 0) + 1
        cap = 60 if cat == "endpoint" else 4
        if len(h["samples"]) < cap and sample not in h["samples"]:
            h["samples"].append(sample)

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        rep["warnings"].append("not a zip archive — cannot read as apk/ipa")
        return rep

    with zf:
        names = zf.namelist()
        rep["entries"] = len(names)
        is_ios = any(n.startswith("Payload/") for n in names)
        rep["platform"] = "ios" if is_ios else "android"
        rep["stack"] = detect_stack(names)

        # --- identity -------------------------------------------------------
        if is_ios:
            rep["identity"] = ios_identity(zf, names, rep)
        else:
            rep["identity"] = android_identity(zf, names, path, rep)

        # nested artifacts (xapk/apks bundles): report and recurse at the caller's level
        nested = [n for n in names if n.lower().endswith(ARTIFACT_EXT)]
        if nested:
            rep["warnings"].append("bundle contains nested artifacts: %s — extract and triage each"
                                   % ", ".join(nested[:6]))

        # --- byte scan ------------------------------------------------------
        patterns = INDICATORS + list(extra_patterns)
        for info in zf.infolist():
            n = info.filename
            low = n.lower()
            interesting = low.endswith(SCAN_SUFFIXES) or "/lib/" in low or low.startswith("lib/") \
                or re.search(r"payload/[^/]+\.app/[^/.]+$", low) is not None \
                or low.endswith("androidmanifest.xml") \
                or (any(seg in low for seg in SCAN_PATHS) and info.file_size <= SCAN_PATH_MAX
                    and not low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ttf", ".otf",
                                          ".woff", ".woff2", ".mp3", ".mp4", ".wav", ".svg", ".ico")))
            if not interesting or info.is_dir():
                continue
            if verbose:
                print("  scanning %s (%d bytes)" % (n, info.file_size), file=sys.stderr)
            try:
                scan_entry(zf, info, patterns, add_hit, cand, pems)
            except Exception as exc:                       # keep going on one bad entry
                rep["warnings"].append("scan failed for %s: %s" % (n, exc))

        # --- DEX string tables (clean literals, no decompiler needed) --------
        for info in zf.infolist():
            if not info.filename.lower().endswith(".dex"):
                continue
            try:
                buf = zf.read(info)
            except Exception:
                continue
            strs = list(dex_strings(buf))
            key_candidates(strs, info.filename, cand)
            for s in strs:
                if s.startswith("L") and s.endswith(";") and CODE_NAME_INTEREST.search(s):
                    code[s] = code.get(s, 0) + 1
            for cat, label, rx in patterns:
                for s in strs:
                    if rx.search(s.encode("utf-8", "replace")):
                        add_hit(cat, label, clip(s), info.filename)
                        if cat != "endpoint":
                            break

    # --- assemble -----------------------------------------------------------
    ordered = sorted(hits.values(), key=lambda h: (
        {"cipher": 0, "structure": 1, "kdf": 2, "mac": 3, "jscrypto": 4, "custom": 5,
         "exchange": 5, "pinning": 6, "endpoint": 7}.get(h["category"], 9), -h["count"]))
    for h in ordered:
        h["where"] = sorted(h["where"].items(), key=lambda kv: -kv[1])[:5]
        rep["hits"].setdefault(h["category"], []).append(h)

    rep["endpoints"] = collect_endpoints(rep["hits"].get("endpoint", []))
    rep["hits"].pop("endpoint", None)
    rep["pem"] = [{"type": re.search(r"BEGIN ([A-Z0-9 ]+)", p).group(1),
                   "bytes": len(p), "sources": sorted(src)[:3], "pem": p}
                  for p, src in sorted(pems.items())][:12]
    rep["code_names"] = [n for n, _ in sorted(code.items(), key=lambda kv: (-kv[1], kv[0]))[:20]]
    top = sorted(cand.values(), key=lambda c: (-c["score"], c["value"]))[:25]
    for c in top:
        c["sources"] = sorted(c["sources"])[:3]
    rep["key_candidates"] = top
    rep["next_steps"] = next_steps(rep)
    return rep


TEXTISH = (".js", ".jsbundle", ".bundle", ".mjs", ".cjs", ".ts", ".json", ".html", ".htm", ".xml",
           ".properties", ".txt", ".yaml", ".yml", ".env", ".plist", ".conf", ".cfg", ".pem", ".jwk",
           ".vue", ".map")


def scan_entry(zf, info, patterns, add_hit, cand, pems: dict):
    """Stream one entry: run every indicator, harvest literals, extract PEM blocks."""
    read = 0
    tail = b""
    collected: list[str] = []
    quoted: list[str] = []
    textish = info.filename.lower().endswith(TEXTISH)
    with zf.open(info) as fh:
        while read < MAX_ENTRY_SCAN:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            read += len(chunk)
            blob = tail + chunk
            for cat, label, rx in patterns:
                if cat == "endpoint":                       # keep every URL, they are the target list
                    for i, m in enumerate(rx.finditer(blob)):
                        if i >= 60:
                            break
                        add_hit(cat, label, clip(printable(m.group(0))), info.filename)
                else:
                    m = rx.search(blob)
                    if m:
                        add_hit(cat, label, clip(printable(m.group(0))), info.filename)
            for m in PEM_BLOCK.finditer(blob):
                pem = m.group(0).decode("ascii", "replace")
                pems.setdefault(pem, set()).add(info.filename)
            # literals: text entries yield short strings, binaries need a longer floor
            text = blob.decode("utf-8", "replace") if textish else blob.decode("latin-1")
            collected.extend(re.findall(r"[\x21-\x7e]{8,200}" if textish else r"[\x21-\x7e]{12,200}", text))
            # quoted literals: a key/passphrase in source is almost always inside quotes, and the
            # surrounding code would otherwise swallow it into one long run
            quoted.extend(re.findall(r"""['"`]([\x20-\x7e]{6,120}?)['"`]""", text))
            tail = blob[-4096:]
    if collected:
        key_candidates(collected[:200000], info.filename, cand)
    if quoted:
        key_candidates(quoted[:200000], info.filename, cand, quoted=True)


def collect_endpoints(endpoint_hits):
    urls = set()
    for h in endpoint_hits:
        urls.update(h["samples"])
    hosts: dict = {}
    for u in urls:
        m = re.match(r"(https?|wss?)://([^/:\s]+)", u)
        if m:
            hosts.setdefault(m.group(2), set()).add(u)
    return [{"host": k, "sample": sorted(v)[0]} for k, v in sorted(hosts.items())][:40]


def android_identity(zf, names, path, rep) -> dict:
    ident: dict = {}
    for tool, args in (("aapt", ["dump", "badging", path]), ("apkanalyzer", ["manifest", "print", path])):
        if shutil.which(tool):
            try:
                out = subprocess.run([tool] + args, capture_output=True, text=True, timeout=120).stdout
                m = re.search(r"package: name='([^']+)'.*?versionName='([^']*)'", out, re.S)
                if m:
                    ident["package"], ident["versionName"] = m.group(1), m.group(2)
                    ident["source"] = tool
                elif "package=" in out:
                    ident["package"] = re.search(r'package="([^"]+)"', out).group(1)
                    ident["source"] = tool
                break
            except Exception:
                pass
    if "AndroidManifest.xml" in names:
        try:
            facts = android_manifest_facts(zf.read("AndroidManifest.xml"))
            ident.setdefault("package", facts.get("package"))
            ident.setdefault("versionName", facts.get("versionName"))
            ident["flags"] = facts["flags"]
            ident["exported"] = facts["exported"][:15]
            ident["deeplinks"] = facts["deeplinks"]
            if not facts["manifest_parsed"]:
                rep["warnings"].append("binary manifest only partially parsed — confirm with aapt/apktool")
        except Exception as exc:
            rep["warnings"].append("manifest parse failed: %s" % exc)
    nsc = [n for n in names if "network_security_config" in n.lower()]
    if nsc:
        try:
            els, strings = parse_axml(zf.read(nsc[0]))
            ident["network_security_config"] = {
                "file": nsc[0],
                "elements": [t for t, _ in els][:20],
                "strings": [s for s in strings if s][:25],
            }
        except Exception:
            ident["network_security_config"] = {"file": nsc[0], "note": "unparsed"}
    return ident


def ios_identity(zf, names, rep) -> dict:
    ident: dict = {}
    plists = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
    if not plists:
        return ident
    try:
        pl = plistlib.loads(zf.read(plists[0]))
    except Exception as exc:
        rep["warnings"].append("Info.plist parse failed: %s" % exc)
        return ident
    ident["bundle_id"] = pl.get("CFBundleIdentifier")
    ident["version"] = pl.get("CFBundleShortVersionString")
    ident["executable"] = pl.get("CFBundleExecutable")
    schemes = []
    for t in pl.get("CFBundleURLTypes", []) or []:
        schemes.extend(t.get("CFBundleURLSchemes", []) or [])
    ident["url_schemes"] = schemes[:20]
    ats = pl.get("NSAppTransportSecurity")
    if ats:
        ident["ats"] = {k: v for k, v in ats.items() if k != "NSExceptionDomains"}
        if "NSExceptionDomains" in ats:
            ident["ats"]["exception_domains"] = list(ats["NSExceptionDomains"].keys())[:20]
    return ident


def next_steps(rep) -> list[str]:
    steps = []
    cats = rep["hits"]
    labels = {h["label"] for hs in cats.values() for h in hs}

    if any("JWE" in l or "JOSE" in l for l in labels):
        steps.append("JWE/JOSE indicators: expect a 5-part compact token on the wire. Check the "
                     "wrapped-key segment on a real sample: empty means the key comes from a handshake; "
                     "populated means it is RSA-wrapped per message. Either way the proxy-side key swap "
                     "gets you the key — see references/key-exchange-mitm.md.")
    if any("RSA" in l for l in labels) and any("AES" in l for l in labels):
        steps.append("RSA + AES together: almost certainly hybrid (RSA wraps a per-session AES key). "
                     "Find where the RSA public key comes from (embedded vs served) — that decides "
                     "between key-swap MITM and runtime capture.")
    if any("PEM public key" in l for l in labels):
        steps.append("Embedded PEM public key: candidate for the key-swap MITM (patch the app's public key "
                     "with yours, decrypt with your private key, re-encrypt with the original).")
    if any("PEM private key" in l for l in labels):
        if any(h["category"] == "exchange" for hs in cats.values() for h in hs) or \
                any("RSA" in l or "JWE" in l for l in labels):
            steps.append("Embedded PRIVATE key **and** key-exchange indicators: the app's own keypair may "
                         "be hardcoded instead of generated per session. Decrypt the handshake's wrapped-key "
                         "blob with it (`crypto-cli.py dec --engine rsa --priv file:<extracted .pem>`) — if "
                         "that works you need no key swap, no patched client, and it works on captures you "
                         "already have.")
        else:
            steps.append("Embedded PRIVATE key: try it directly — the whole scheme may be readable with no "
                         "runtime work at all.")
    if any("PKCS12 / keystore file" in l for l in labels):
        steps.append("A keystore/PKCS#12 file ships with the app: extract it and look for its password in "
                     "the code (`openssl pkcs12 -in <file> -nodes`). A shipped private key beats every "
                     "other route.")
    if any(c["score"] >= 85 for c in rep["key_candidates"]):
        steps.append("High-confidence key candidates found: test each against a captured ciphertext with "
                     "crypto-cli.py before doing any runtime work.")
    if any("PBKDF2" in l or "EVP_BytesToKey" in l or "scrypt" in l for l in labels):
        steps.append("Key derivation present: the shipped literal is likely a *password*, not the key. "
                     "Reproduce the KDF (salt + iterations + digest) exactly.")
    if any("Hmac" in l or "signature header" in l for l in labels):
        steps.append("MAC/signature indicators: the body is probably signed. Identify the signed input and "
                     "the MAC key or edits will be rejected — see references/integrity-and-signatures.md.")
    if any(h["category"] == "exchange" for hs in cats.values() for h in hs):
        steps.append("Key-exchange indicators (handshake endpoint / runtime keypair / JWK delivery): the "
                     "symmetric key is NEGOTIATED, so there is nothing to extract statically. Capture "
                     "the exchange in the proxy and swap the client public key — or patch the client to "
                     "use a keypair you own. See references/key-exchange-mitm.md and patch-the-client.md.")
    if any("X25519" in l or "ECDH" in l for l in labels) and any("RSA" in l for l in labels):
        steps.append("Two key-exchange schemes present (RSA and X25519/ECDH): apps ship an alternative "
                     "crypto model behind a flag. Confirm from live traffic which one is active — the "
                     "wrong assumption invalidates the whole setup.")
    if any("Android Keystore" in l for l in labels):
        steps.append("AndroidKeyStore in use: the key may be hardware-backed, so no key bytes exist to "
                     "find statically. Prefer patching the client to log/replace the key, or capture the "
                     "key exchange in the proxy; instrumentation is the last resort.")
    if any("CryptoJS" in l or "WebCrypto" in l or "JSEncrypt" in l or "sjcl" in l for l in labels):
        steps.append("JS-side crypto: read the bundle directly (js-beautify) — it states the mode, key and "
                     "IV handling outright. Mind the library defaults before assuming anything: see "
                     "references/js-crypto-defaults.md.")
    if any("passphrase form" in l for l in labels):
        steps.append("CryptoJS was called with a STRING key: that is a passphrase, not a key — AES-256-CBC "
                     "with EVP_BytesToKey(MD5) + salt, wire format 'U2FsdGVkX1…'. Decrypt with "
                     "`crypto-cli.py dec --structure openssl --kdf evp-md5 --key utf8:<literal>`; feeding "
                     "the literal as raw key bytes yields garbage.")
    if any("raw-key form" in l for l in labels):
        steps.append("CryptoJS was called with a parsed (raw) key: no KDF, key length = the literal's "
                     "length, and an explicit IV is mandatory — find the IV literal next to the key.")
    if not steps:
        steps.append("No decisive crypto indicators. Confirm the traffic really is encrypted (run "
                     "ciphertext-analyze.py on a captured request) before spending time on the binary.")
    return steps


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def render_md(rep) -> str:
    L = []
    ident = rep["identity"]
    name = ident.get("package") or ident.get("bundle_id") or os.path.basename(rep["artifact"])
    L.append("# Crypto triage — %s" % name)
    L.append("")
    L.append("- **Artifact:** `%s` (%.1f MB, sha256 `%s`)" % (rep["artifact"], rep["size"] / 1e6, rep["sha256"][:16]))
    L.append("- **Platform:** %s · %d zip entries" % (rep["platform"], rep["entries"]))
    L.append("- **Stack:** %s" % "; ".join(rep["stack"]))
    for k in ("package", "bundle_id", "versionName", "version", "executable"):
        if ident.get(k):
            L.append("- **%s:** %s" % (k, ident[k]))
    if ident.get("flags"):
        L.append("- **Manifest flags:** %s" % json.dumps(ident["flags"]))
    if ident.get("ats"):
        L.append("- **ATS:** %s" % json.dumps(ident["ats"]))
    if ident.get("network_security_config"):
        L.append("- **network_security_config:** `%s` → %s" % (
            ident["network_security_config"].get("file"),
            ", ".join(ident["network_security_config"].get("strings", [])[:12]) or "unparsed"))
    if ident.get("url_schemes"):
        L.append("- **URL schemes:** %s" % ", ".join(ident["url_schemes"]))
    if ident.get("deeplinks"):
        L.append("- **Deep links:** %s" % ", ".join(ident["deeplinks"]))
    L.append("")

    L.append("## Crypto indicators")
    if not rep["hits"]:
        L.append("_none_")
    for cat, hs in rep["hits"].items():
        L.append("")
        L.append("### %s" % cat)
        for h in hs:
            where = ", ".join("%s×%d" % (w, c) for w, c in h["where"])
            L.append("- **%s** (%d hits) — %s" % (h["label"], h["count"], where))
            for s in h["samples"]:
                L.append("  - `%s`" % s)
    L.append("")

    L.append("## Key-material candidates (leads — prove by decrypting a real sample)")
    if not rep["key_candidates"]:
        L.append("_none of the expected shapes_")
    for c in rep["key_candidates"]:
        L.append("- `%s`  — %s  _(score %d; %s)_" % (clip(c["value"], 90), c["why"], c["score"],
                                                     ", ".join(c["sources"])))
    L.append("")

    if rep["pem"]:
        L.append("## Embedded PEM blocks")
        for p in rep["pem"]:
            L.append("- **%s** (%d bytes) in %s" % (p["type"], p["bytes"], ", ".join(p["sources"])))
        L.append("")
        L.append("_With `--out DIR` each block is written to `DIR/<artifact>.pem.<n>` — feed a public key "
                 "straight into the key-swap workflow, a private key straight into crypto-cli.py._")
        L.append("")

    if rep["code_names"]:
        L.append("## Classes to open first (jadx)")
        L.append("`%s`" % "`, `".join(rep["code_names"]))
        L.append("")

    if rep["endpoints"]:
        L.append("## Hosts seen in the artifact")
        for e in rep["endpoints"]:
            L.append("- `%s`  (e.g. %s)" % (e["host"], clip(e["sample"], 90)))
        L.append("")

    L.append("## What to do next")
    for s in rep["next_steps"]:
        L.append("- %s" % s)
    if rep["warnings"]:
        L.append("")
        L.append("## Warnings")
        for w in rep["warnings"]:
            L.append("- %s" % w)
    L.append("")
    return "\n".join(L)


def find_artifacts(paths):
    found = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    if f.lower().endswith(ARTIFACT_EXT):
                        found.append(os.path.join(root, f))
        elif os.path.isfile(p):
            found.append(p)
        else:
            print("skip (not found): %s" % p, file=sys.stderr)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", metavar="PATH", help="artifact files and/or directories to walk")
    ap.add_argument("--out", metavar="DIR", help="write <name>.triage.md and .triage.json per artifact")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--grep", action="append", default=[], metavar="REGEX",
                    help="extra indicator regex (repeatable), reported under category 'custom'")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every entry scanned to stderr")
    args = ap.parse_args()

    extra = [(("custom"), "custom: %s" % g, re.compile(g.encode())) for g in args.grep]
    artifacts = find_artifacts(args.paths)
    if not artifacts:
        print("no apk/ipa/aab/xapk artifacts found", file=sys.stderr)
        return 1
    if args.out:
        os.makedirs(args.out, exist_ok=True)

    reports = []
    for a in artifacts:
        print("[*] triaging %s" % a, file=sys.stderr)
        rep = triage(a, extra, verbose=args.verbose)
        reports.append(rep)
        md = render_md(rep)
        if args.out:
            stem = os.path.join(args.out, re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(a)))
            with open(stem + ".triage.md", "w") as fh:
                fh.write(md)
            with open(stem + ".triage.json", "w") as fh:
                json.dump(rep, fh, indent=2, default=str)
            for i, p in enumerate(rep["pem"]):
                with open("%s.pem.%d" % (stem, i), "w") as fh:
                    fh.write(p["pem"] + "\n")
            # a plain candidate list, ready for: crypto-cli.py solve --key-candidates <file>
            with open("%s.keys.txt" % stem, "w") as fh:
                fh.write("# candidate key literals from %s — feed to `crypto-cli.py solve "
                         "--key-candidates`\n" % os.path.basename(a))
                for c in rep["key_candidates"]:
                    fh.write("%s\n" % c["value"])
            print("    -> %s.triage.md / .json / .keys.txt%s"
                  % (stem, " (+%d PEM)" % len(rep["pem"]) if rep["pem"] else ""), file=sys.stderr)
        if not args.json:
            print(md)
    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
