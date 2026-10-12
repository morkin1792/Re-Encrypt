#!/usr/bin/env python3
"""
emit-reencrypt-config.py — turn a crypto profile into a Re:Encrypt setup you can act on now.

Input: the profile JSON you wrote after identifying the scheme (assets/crypto-profile.schema.json).
Output, into --out DIR:
  * `reencrypt-config.json` — the proposed import format (assets/reencrypt-config.schema.json).
    Re:Encrypt cannot import it yet, so it is the machine-readable record of the decision and the
    file to feed the importer once it lands.
  * `RUNBOOK.md` — what to fill in, field by field, in the Re:Encrypt Settings tab **today**, plus
    the equivalent `crypto-cli.py` custom-command pair (works in any Re:Encrypt build, and outside
    Burp entirely), plus the verification steps and every open risk.

  emit-reencrypt-config.py profile.json --out workspace/proj/crypto/
  emit-reencrypt-config.py profile.json --check            # validate + list gaps, write nothing
  emit-reencrypt-config.py profile.json --cli-path ./crypto-cli.py --print
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

PATTERN_TYPE = {
    "header": "Header",
    "url_param": "Parameter (URL-encoded)",
    "json_param": "Parameter (JSON)",
    "whole_body": "Whole Body",
    "custom_regex": "Custom Regex",
}
KEY_FORMAT_TO_CLI = {"Hex": "hex", "Base64": "b64", "Base64URL": "b64u", "UTF-8": "utf8"}


# ---------------------------------------------------------------------------
# capture regex (mirrors reencrypt.PatternType.buildRegex — group 1 = ciphertext)
# ---------------------------------------------------------------------------

def build_regex(loc: dict) -> str:
    if loc.get("regex"):
        return loc["regex"]
    t, inp = loc.get("type"), loc.get("input") or ""
    if t == "header":
        return "(?i)%s: (.*)" % inp
    if t == "url_param":
        return "%s=(.*?)(?:&|$)" % inp
    if t == "json_param":
        return '"%s":"(.*?)"' % inp
    if t == "whole_body":
        return r"(?s)(?<=\r\n\r\n)(.+)"
    return inp


# ---------------------------------------------------------------------------
# profile -> engineParams
# ---------------------------------------------------------------------------

def material_params(prefix: str, mat: dict, out: dict, file_format=False):
    if not mat:
        return
    src = mat.get("source") or ("text" if mat.get("value") else None)
    if mat.get("value") is not None:
        out[prefix] = mat["value"]
    if src:
        out[prefix + "Source"] = src
    fmt = mat.get("format")
    if fmt:
        if file_format and fmt in ("PEM", "DER"):
            out[prefix + "FileFormat"] = fmt
        elif fmt not in ("PEM", "DER"):
            out[prefix + "Format"] = fmt
    if src == "file":
        # re-read per operation: this is what makes a rotating key work unattended
        out[prefix + "ReloadFile"] = "true" if mat.get("rotates", True) else "false"


def engine_params(c: dict) -> dict:
    p: dict = {}
    if c["engine"] == "aes":
        p["mode"] = c.get("mode", "CBC")
        p["ciphertextStructure"] = c.get("structure", "raw")
        p["encoding"] = c.get("encoding", "Base64")
        p["mirrorEncoding"] = "true"
        if p["mode"] in ("CBC", "ECB"):
            p["padding"] = c.get("padding", "PKCS5Padding")
        if c.get("ivLength"):
            p["ivLength"] = str(c["ivLength"])
        if p["mode"] == "GCM":
            p["gcmTagLength"] = str(c.get("gcmTagLength", 128))
        if p["ciphertextStructure"] == "openssl":
            p["keyDerivation"] = c.get("keyDerivation", "evp_md5")
            if p["keyDerivation"] == "pbkdf2":
                p["pbkdf2Iterations"] = str(c.get("pbkdf2Iterations", 10000))
            p["opensslKeyLength"] = str(c.get("keyLength", 32))
        material_params("key", c.get("key"), p)
        material_params("iv", c.get("iv"), p)
    elif c["engine"] == "rsa":
        scheme = (c.get("rsaScheme") or "PKCS1").upper()
        if scheme.startswith("OAEP"):
            p["encryptionScheme"] = "OAEP"
            p["oaepDigest"] = "SHA-256" if scheme.endswith("256") else "SHA-1"
        elif scheme == "RAW":
            p["encryptionScheme"] = "Raw"
        else:
            p["encryptionScheme"] = "PKCS1"
        p["encoding"] = c.get("encoding", "Base64")
        p["mirrorEncoding"] = "true"
        material_params("publicKey", c.get("publicKey"), p, file_format=True)
        material_params("privateKey", c.get("privateKey"), p, file_format=True)
    return p


# ---------------------------------------------------------------------------
# profile -> crypto-cli command pair (works today, and outside Burp)
# ---------------------------------------------------------------------------

def cli_commands(field: dict, cli_path: str) -> tuple:
    c = field["crypto"]
    if c["engine"] == "custom":
        cc = field.get("customCommand") or {}
        return cc.get("decrypt", "<your decrypt command, reading {FILE}>"), \
            cc.get("encrypt", "<your encrypt command, reading {FILE}>")

    common = []
    if c["engine"] == "rsa":
        common += ["--engine", "rsa"]
        scheme = {"PKCS1": "pkcs1", "OAEP-SHA1": "oaep-sha1", "OAEP-SHA256": "oaep-sha256"}.get(
            (c.get("rsaScheme") or "PKCS1").upper(), "pkcs1")
        common += ["--rsa-scheme", scheme]
        if c.get("privateKey"):
            common += ["--priv", material_spec(c["privateKey"], pem=True)]
        if c.get("publicKey"):
            common += ["--pub", material_spec(c["publicKey"], pem=True)]
    else:
        common += ["--mode", c.get("mode", "CBC"), "--structure", c.get("structure", "raw")]
        enc = {"Base64": "base64", "Base64URL": "base64url", "Hex": "hex", "Raw": "raw"}.get(
            c.get("encoding", "Base64"), "base64")
        common += ["--encoding", enc]
        if c.get("padding") == "NoPadding":
            common += ["--padding", "none"]
        if c.get("ivLength"):
            common += ["--iv-length", str(c["ivLength"])]
        if c.get("mode") == "GCM" and c.get("gcmTagLength"):
            common += ["--tag-length", str(c["gcmTagLength"])]
        if c.get("structure") == "openssl":
            common += ["--kdf", {"evp_md5": "evp-md5", "evp_sha256": "evp-sha256",
                                 "pbkdf2": "pbkdf2"}.get(c.get("keyDerivation", "evp_md5"))]
        if c.get("structure") == "jwe":
            common += ["--jwe-state", "/tmp/jwe-state.json"]
            if c.get("privateKey"):
                common += ["--priv", material_spec(c["privateKey"], pem=True)]
        if c.get("key"):
            common += material_key_args(c["key"])
        if c.get("iv"):
            common += ["--iv", material_spec(c["iv"])]
    opts = " ".join(_quote(o) for o in common)
    # --quiet is not optional in a proxy command: Re:Encrypt merges stderr into the command output
    return ("python3 %s dec %s --quiet --in-file {FILE}" % (cli_path, opts),
            "python3 %s enc %s --quiet --in-file {FILE}" % (cli_path, opts))


def _quote(tok: str) -> str:
    return tok if re.fullmatch(r"[A-Za-z0-9_.,:/=+@%{}-]*", tok) else "'%s'" % tok.replace("'", "'\\''")


def material_key_args(mat: dict) -> list:
    """A key log needs --key-log/--session; anything else is a plain --key spec."""
    if mat.get("keyLog"):
        args = ["--key-log", mat["keyLog"]]
        if mat.get("session"):
            args += ["--session", mat["session"]]
        return args
    return ["--key", material_spec(mat)]


def material_spec(mat: dict, pem=False) -> str:
    src = mat.get("source") or "text"
    val = mat.get("value") or "<missing>"
    fmt = mat.get("format")
    if src == "file":
        if pem or fmt in ("PEM", "DER"):
            return "file:%s" % val
        return "file:%s:%s" % (KEY_FORMAT_TO_CLI.get(fmt, "hex"), val)
    if src == "command":
        return "cmd:%s" % val
    if pem:
        return val
    return "%s:%s" % (KEY_FORMAT_TO_CLI.get(fmt, "hex"), val)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def validate(profile: dict) -> list:
    warn = []
    if profile.get("schemaVersion") != "1":
        warn.append("schemaVersion should be \"1\"")
    for f in profile.get("fields", []):
        n = f.get("name", "?")
        c = f.get("crypto", {})
        loc = f.get("location", {})
        if loc.get("type") in ("header", "url_param", "json_param") and not loc.get("input") \
                and not loc.get("regex"):
            warn.append("%s: location.type=%s needs `input` (the header/param name)" % (n, loc.get("type")))
        if loc.get("type") == "custom_regex":
            rx = loc.get("regex") or loc.get("input") or ""
            if "(" not in rx:
                warn.append("%s: a custom regex must contain capturing group 1 = the ciphertext span" % n)
            else:
                try:
                    re.compile(rx)
                except re.error as exc:
                    warn.append("%s: capture regex does not compile: %s" % (n, exc))
        if c.get("engine") == "custom" and not (f.get("customCommand") or {}).get("decrypt"):
            warn.append("%s: engine=custom but no customCommand.decrypt" % n)
        key = c.get("key") or {}
        if c.get("engine") == "aes" and c.get("structure") != "jwe":
            if not key:
                warn.append("%s: no key at all — the setup cannot work yet; finish the key hunt" % n)
            elif key.get("acquisition") == "unknown":
                warn.append("%s: key acquisition is 'unknown' — decide static / derived / runtime / "
                            "exchange before configuring anything" % n)
            elif not key.get("value"):
                warn.append("%s: key has no value/path/command" % n)
            if key.get("keyLog") and not key.get("value"):
                warn.append("%s: the key comes from a key log — the built-in AES engine needs a single "
                            "value, so use the generated custom-command pair (it passes --key-log), or "
                            "have the capture also write a one-line latest-key file and set key.value "
                            "to it" % n)
            if key.get("rotates") and key.get("source") == "text":
                warn.append("%s: the key rotates but is configured as literal text — use source=file "
                            "(with a live key file) or source=command so it is re-read per request" % n)
            if c.get("structure") == "raw" and c.get("mode") not in ("ECB", None) and not c.get("iv"):
                warn.append("%s: structure=raw with mode=%s but no IV configured" % (n, c.get("mode")))
        if c.get("structure") == "jwe" and not (c.get("key") or c.get("privateKey")):
            warn.append("%s: JWE needs either the captured CEK (crypto.key) or your private key "
                        "(crypto.privateKey) after a key swap" % n)
        if c.get("engine") == "rsa" and not (c.get("privateKey") or c.get("publicKey")):
            warn.append("%s: engine=rsa with no key material" % n)
        v = f.get("verified") or {}
        if not v.get("decrypt"):
            warn.append("%s: UNVERIFIED — no captured sample has decrypted yet. Prove it with "
                        "crypto-cli.py before trusting this config" % n)
    for i in profile.get("integrity", []):
        if not i.get("handled"):
            warn.append("integrity field %s is not handled — edited requests will be rejected until "
                        "you recompute it" % i.get("field"))
    return warn


# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------

def to_config(profile: dict) -> dict:
    target = profile.get("target") or {}
    cfg = {
        "formatVersion": 1,
        "generatedBy": "decrypt-app-traffic skill / emit-reencrypt-config.py",
        "note": "Proposed import format — see assets/reencrypt-config.schema.json. Until Re:Encrypt "
                "can import it, follow RUNBOOK.md.",
        "requestPatterns": [],
        "responsePatterns": [],
        "settings": {"enableRequestPrintEditor": True, "enableResponsePrintEditor": True},
    }
    for f in profile.get("fields", []):
        c = f.get("crypto", {})
        loc = f.get("location", {})
        pat = {
            "name": f.get("name", "pattern"),
            "enabled": True,
            "patternType": PATTERN_TYPE.get(loc.get("type"), "Custom Regex"),
            "patternInput": loc.get("input", ""),
            "captureRegex": build_regex(loc),
            "urlTargetRegex": "" if target.get("useProjectScope") else target.get("urlRegex", ""),
            "useProjectScope": bool(target.get("useProjectScope")),
            "patchProxy": bool(f.get("patchProxy")),
            "useCacheSystem": f.get("useCache", True),
            "saveToLog": f.get("saveToLog", True),
            "detectGarbage": True,
        }
        if c.get("engine") in ("aes", "rsa"):
            pat["engineId"] = c["engine"]
            pat["engineParams"] = engine_params(c)
        else:
            pat["engineId"] = None
            cc = f.get("customCommand") or {}
            pat["decCommand"] = cc.get("decrypt", "")
            pat["encCommand"] = cc.get("encrypt", "")
        key = "requestPatterns" if f.get("direction") == "request" else "responsePatterns"
        cfg[key].append(pat)
    return cfg


def runbook(profile: dict, cfg: dict, warnings: list, cli_path: str) -> str:
    app = profile.get("app", {})
    target = profile.get("target") or {}
    L = ["# Re:Encrypt runbook — %s" % (app.get("id") or "target app"), ""]
    L.append("Platform **%s**%s%s. Generated from the crypto profile; every value below is a decision "
             "recorded there." % (app.get("platform", "?"),
                                  " · app version %s" % app["version"] if app.get("version") else "",
                                  " · stack %s" % app["stack"] if app.get("stack") else ""))
    L.append("")
    if target.get("hosts"):
        L.append("Target hosts: %s" % ", ".join("`%s`" % h for h in target["hosts"]))
        L.append("")

    if warnings:
        L.append("## Before you start — open gaps")
        L.append("")
        for w in warnings:
            L.append("- %s" % w)
        L.append("")

    L.append("## 1. Load the extension")
    L.append("")
    L.append("Burp → Extensions → Installed → Add → `re-encrypt.jar`, then open the **Re:Encrypt** tab.")
    L.append("")

    step = 1
    for f in profile.get("fields", []):
        step += 1
        c = f.get("crypto", {})
        loc = f.get("location", {})
        L.append("## %d. Pattern `%s` (%s)" % (step, f.get("name"), f.get("direction")))
        L.append("")
        L.append("In **Capturing + Processing**, add a %s pattern:" % f.get("direction"))
        L.append("")
        L.append("| Field | Value |")
        L.append("|---|---|")
        L.append("| Name | `%s` |" % f.get("name"))
        L.append("| What will be captured | **%s** |" % PATTERN_TYPE.get(loc.get("type"), "Custom Regex"))
        if loc.get("input"):
            L.append("| Parameter / header name | `%s` |" % loc["input"])
        L.append("| Effective regex (group 1 = ciphertext) | `%s` |" % build_regex(loc))
        if target.get("useProjectScope"):
            L.append("| URL targeting | use Burp project scope |")
        elif target.get("urlRegex"):
            L.append("| URL target regex | `%s` |" % target["urlRegex"])
        L.append("| Patch proxy | %s |" % ("**on** — needed here" if f.get("patchProxy") else "off"))
        L.append("| Cache | %s |" % ("on" if f.get("useCache", True) else "off"))
        L.append("")

        if c.get("engine") in ("aes", "rsa"):
            L.append("Encryption Mode → **%s**, then:" % c["engine"].upper())
            L.append("")
            L.append("| Engine setting | Value |")
            L.append("|---|---|")
            for k, v in engine_params(c).items():
                L.append("| `%s` | `%s` |" % (k, v))
            L.append("")
            if (c.get("key") or {}).get("source") == "file":
                L.append("The key comes from a **file** — keep *reload file on every operation* on, so a "
                         "rotating key is picked up without touching the UI. Whatever captures the key "
                         "(proxy-side patcher, patched client, or frida-run.py) must keep `%s` current."
                         % (c["key"].get("value")))
                if c["key"].get("keyLog"):
                    L.append("")
                    L.append("For offline, session-accurate work use the key log instead: "
                             "`crypto-cli.py keys --key-log %s --session <sid>`. In-proxy there is no "
                             "session context, so the file/newest key is what you get — keep one "
                             "session live at a time." % c["key"]["keyLog"])
                L.append("")
            if c.get("structure") == "jwe":
                L.append("JWE note: decrypt a captured token **first** — the engine remembers the protected "
                         "header and the wrapped key from that message and reuses them when re-encrypting.")
                L.append("")

        dec, enc = cli_commands(f, cli_path)
        L.append("Equivalent **Custom Command** pair (works in any build, and outside Burp):")
        L.append("")
        L.append("```bash")
        L.append("# Decrypt Command")
        L.append(dec)
        L.append("# Encrypt Command")
        L.append(enc)
        L.append("```")
        L.append("")
        key_notes = [(name, m) for name, m in (("key", c.get("key")), ("IV", c.get("iv")),
                                               ("public key", c.get("publicKey")),
                                               ("private key", c.get("privateKey"))) if m]
        if key_notes:
            L.append("Key material:")
            for name, m in key_notes:
                L.append("- **%s** — %s%s%s" % (
                    name, m.get("acquisition", "?"),
                    ", read as `%s` from %s" % (m.get("format", "?"), m.get("source", "text")),
                    " · %s" % m["notes"] if m.get("notes") else ""))
            L.append("")

    if profile.get("integrity"):
        step += 1
        L.append("## %d. Integrity fields — handle these or edits get rejected" % step)
        L.append("")
        for i in profile["integrity"]:
            L.append("- **%s** (%s) over `%s`%s — %s" % (
                i.get("field"), i.get("algorithm", "?"), i.get("signedInput", "?"),
                " · key %s" % (i.get("key") or {}).get("acquisition", "?") if i.get("key") else "",
                "handled" if i.get("handled") else "**NOT handled yet**"))
        L.append("")
        L.append("The clean way: make the encrypt command recompute the MAC and emit both values, or "
                 "put the MAC in its own pattern whose 'encrypt' step signs the ciphertext.")
        L.append("")

    step += 1
    L.append("## %d. Verify, in this order" % step)
    L.append("")
    L.append("1. **Decrypt a captured sample offline** with the command above — you must see plaintext "
             "you recognise. Nothing else counts as confirmation.")
    L.append("2. **Round-trip:** decrypt then re-encrypt the same payload unchanged and send it. A 200 "
             "with the same response as the original proves the encrypt path.")
    L.append("3. **Change one harmless value** (a display name, a page number), re-send, and confirm the "
             "server acted on the change. That proves the whole chain, including any signature.")
    L.append("4. Only then start testing. If step 2 or 3 fails, fix the setup — do not test through a "
             "half-working transform, every result will be noise.")
    L.append("")
    if profile.get("notes"):
        L.append("## Notes")
        L.append("")
        for note in profile["notes"]:
            L.append("- %s" % note)
        L.append("")
    L.append("---")
    L.append("`reencrypt-config.json` in this folder holds the same configuration in the proposed "
             "import format (Re:Encrypt cannot read it yet — it is the record and the future one-click "
             "import).")
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profile", help="crypto profile JSON")
    ap.add_argument("--out", help="directory to write reencrypt-config.json + RUNBOOK.md")
    ap.add_argument("--check", action="store_true", help="validate only, write nothing")
    ap.add_argument("--print", dest="do_print", action="store_true", help="print the runbook to stdout")
    ap.add_argument("--cli-path", default="crypto-cli.py",
                    help="path to crypto-cli.py as the proxy will invoke it (use an absolute path)")
    args = ap.parse_args()

    with open(args.profile) as fh:
        profile = json.load(fh)

    warnings = validate(profile)
    cfg = to_config(profile)
    book = runbook(profile, cfg, warnings, args.cli_path)

    if warnings:
        print("%d gap(s) in the profile:" % len(warnings), file=sys.stderr)
        for w in warnings:
            print("  - %s" % w, file=sys.stderr)
    else:
        print("profile is complete and verified", file=sys.stderr)
    if args.check:
        return 1 if warnings else 0

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "reencrypt-config.json"), "w") as fh:
            json.dump(cfg, fh, indent=2)
        with open(os.path.join(args.out, "RUNBOOK.md"), "w") as fh:
            fh.write(book)
        print("wrote %s/reencrypt-config.json and %s/RUNBOOK.md" % (args.out, args.out), file=sys.stderr)
    if args.do_print or not args.out:
        print(book)
    return 0


if __name__ == "__main__":
    sys.exit(main())
