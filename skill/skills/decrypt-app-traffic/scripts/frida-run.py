#!/usr/bin/env python3
"""
frida-run.py — run the crypto hooks and keep a **live key file** the proxy can re-read per request.

This is the glue for rotating keys. Re:Encrypt (and crypto-cli.py) can take the key from a file that
is re-read on every operation, so when the app renews its session key mid-session, decryption keeps
working with no clicking: this script rewrites that file the moment a new key appears.

  frida-run.py com.target.app --key-file /tmp/aes.key
  frida-run.py com.target.app --spawn --log workspace/proj/crypto/events.jsonl
  frida-run.py TargetApp --platform ios --key-file /tmp/aes.key --key-format hex
  frida-run.py com.target.app --script my-extra-hooks.js        # add your own on top

Then point Re:Encrypt's AES engine at it:  Key source = File, path = /tmp/aes.key,
format = Hex, "reload file on every operation" = on. Or crypto-cli.py: `--key file:hex:/tmp/aes.key`.

Needs the frida python bindings (`pip install frida-tools`) and a device with frida-server running.
Without them, run the hooks directly — `frida -U -f <pkg> -l frida/hooks-android.js` — and copy keys
by hand; you lose only the automatic key file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCRIPTS = {"android": os.path.join(HERE, "frida", "hooks-android.js"),
                   "ios": os.path.join(HERE, "frida", "hooks-ios.js")}

# events that carry a symmetric key, in the order we prefer them
KEY_EVENTS = ("cipher.init", "key", "CCCryptorCreateWithMode", "CCCryptorCreate", "CCCrypt",
              "native.evp", "PBKDF2")


class KeySink:
    """Writes the newest usable key to --key-file, atomically, and logs every event."""

    def __init__(self, key_file, key_format, iv_file, log_path, min_bytes, quiet,
                 key_log=None, session=None):
        self.key_log = key_log
        self.session = session or "-"
        self.key_file = key_file
        self.key_format = key_format
        self.iv_file = iv_file
        self.log = open(log_path, "a") if log_path else None
        self.min_bytes = min_bytes
        self.quiet = quiet
        self.current_key = None
        self.current_iv = None
        self.keys_seen = 0

    def handle(self, ev: dict):
        if self.log:
            self.log.write(json.dumps(ev) + "\n")
            self.log.flush()
        kind = ev.get("ev")
        key = ev.get("keyHex") or ev.get("hex") or ev.get("derivedKeyHex")
        if kind in KEY_EVENTS and key and _plausible(key, self.min_bytes):
            if key != self.current_key:
                self.current_key = key
                self.keys_seen += 1
                self._write(self.key_file, key)
                self._append_keylog(key)
                self._say("key #%d (%d bytes) %s  [%s%s]" % (
                    self.keys_seen, len(key) // 2, key,
                    kind, " " + ev["transform"] if ev.get("transform") else ""))
                for line in (ev.get("stack") or ev.get("backtrace") or [])[:4]:
                    self._say("    from %s" % line)
        iv = ev.get("ivHex")
        if iv and iv != self.current_iv and _plausible(iv, 8):
            self.current_iv = iv
            self._write(self.iv_file, iv)
        if not self.quiet and kind in ("cipher.doFinal", "CCCrypt", "CCCryptorUpdate"):
            pt = (ev.get("plaintext") or {})
            body = pt.get("text") or pt.get("hex")
            if body:
                self._say("%s %s → %s" % (kind, ev.get("transform") or ev.get("mode") or "",
                                          body[:160]))
        if kind in ("mac.init", "CCHmac") and ev.get("keyHex"):
            self._say("MAC key (%s): %s" % (ev.get("algorithm"), ev["keyHex"]))
        if kind in ("publicKey", "privateKey", "publicKey.parsed") and ev.get("base64"):
            self._say("%s captured (%s) — save it: %s…" % (kind, ev.get("format", ""),
                                                           ev["base64"][:60]))

    def _write(self, path, hexvalue):
        if not path:
            return
        data = hexvalue
        if self.key_format == "base64":
            import base64
            data = base64.b64encode(bytes.fromhex(hexvalue)).decode()
        elif self.key_format == "raw":
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(bytes.fromhex(hexvalue))
            os.replace(tmp, path)
            return
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(data)                      # no trailing newline: proxies pass the file verbatim
        os.replace(tmp, path)

    def _append_keylog(self, hexvalue):
        """Same line format the proxy-side capture writes, so one resolver reads both."""
        if not self.key_log:
            return
        value = hexvalue
        if self.key_format == "base64":
            import base64
            value = base64.b64encode(bytes.fromhex(hexvalue)).decode()
        with open(self.key_log, "a") as fh:
            fh.write("%s: %s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), value, self.session))

    def _say(self, msg):
        print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def _plausible(hexstr, min_bytes: int) -> bool:
    """True for a clean hex string of at least min_bytes that isn't an all-zero placeholder."""
    if not isinstance(hexstr, str):
        return False
    h = hexstr.strip()
    if not h or len(h) % 2 or re.search(r"[^0-9a-fA-F]", h):
        return False
    if len(h) // 2 < min_bytes:
        return False
    return set(h.lower()) != {"0"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="package name / bundle id / process name")
    ap.add_argument("--platform", choices=("android", "ios"), default="android")
    ap.add_argument("--spawn", action="store_true", help="spawn the app (catches startup crypto)")
    ap.add_argument("--device", help="frida device id (default: first USB device)")
    ap.add_argument("--script", action="append", default=[],
                    help="extra frida script to load after the default hooks (repeatable)")
    ap.add_argument("--no-default-script", action="store_true")
    ap.add_argument("--key-file", help="rewrite this file whenever a new symmetric key appears")
    ap.add_argument("--key-log", help="also APPEND '<ts>: <key> <session>' lines here "
                                      "(the format crypto-cli.py --key-log reads)")
    ap.add_argument("--session", help="session id to tag key-log lines with")
    ap.add_argument("--iv-file", help="same for the IV (rarely needed — IVs usually travel inline)")
    ap.add_argument("--key-format", choices=("hex", "base64", "raw"), default="hex")
    ap.add_argument("--min-key-bytes", type=int, default=16,
                    help="ignore shorter key material (default 16)")
    ap.add_argument("--log", help="append every event as JSONL here")
    ap.add_argument("--quiet", action="store_true", help="only report keys, not plaintext")
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        script = DEFAULT_SCRIPTS[args.platform]
        print("frida python bindings not installed (pip install frida-tools).\n"
              "Run the hooks directly instead:\n  frida -U %s %s -l %s"
              % ("-f" if args.spawn else "-n", args.target, script), file=sys.stderr)
        return 2

    sources = []
    if not args.no_default_script:
        sources.append(DEFAULT_SCRIPTS[args.platform])
    sources.extend(args.script)
    code = "\n".join(open(s).read() for s in sources)

    device = frida.get_device(args.device) if args.device else frida.get_usb_device(timeout=10)
    print("device: %s" % device.name)

    if args.spawn:
        pid = device.spawn([args.target])
        session = device.attach(pid)
    else:
        session = device.attach(args.target)
        pid = None

    sink = KeySink(args.key_file, args.key_format, args.iv_file, args.log, args.min_key_bytes,
                   args.quiet, key_log=args.key_log, session=args.session)
    script = session.create_script(code)

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                sink.handle(payload)
            else:
                print(payload, flush=True)
        elif message["type"] == "error":
            print("script error: %s" % message.get("stack") or message, file=sys.stderr)

    script.on("message", on_message)
    script.load()
    if pid:
        device.resume(pid)
    print("hooks loaded%s. Drive the app; keys appear below.%s"
          % (" (spawned)" if pid else "",
             ("\nkey file: %s (%s, rewritten on every new key)" % (args.key_file, args.key_format))
             if args.key_file else ""))
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
        if sink.log:
            sink.log.close()
        print("\n%d distinct key(s) captured." % sink.keys_seen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
