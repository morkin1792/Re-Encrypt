#!/usr/bin/env node
/*
 * js-crypto-oracle.js — decrypt/encrypt with the app's OWN JavaScript crypto library.
 *
 * When an app's crypto is JS (React Native, Cordova/Capacitor, any WebView flow), the shortest path
 * to working traffic is to call the same library the app calls, with the same arguments, instead of
 * re-deriving its defaults. Point this at the library the bundle imports and you inherit every quirk
 * (key derivation, padding, output envelope) for free.
 *
 *   node js-crypto-oracle.js dec --lib cryptojs --key '7x!A%D*G-KaPdSgV' --file {FILE}
 *   node js-crypto-oracle.js enc --lib cryptojs --key-format hex --key 00112233… --iv 0011… --file {FILE}
 *   node js-crypto-oracle.js dec --lib sjcl --key 'passphrase' --file {FILE}
 *   node js-crypto-oracle.js dec --lib auto --file {FILE}          # guess from the payload shape
 *
 * Wire it into Re:Encrypt as the Decrypt/Encrypt Command pair (use {FILE}), or into any proxy script.
 * Writes the result to stdout with no added newline; nothing else is ever written to stdout, so it is
 * safe as a proxy command. Requires the library on the module path:
 *     npm i crypto-js sjcl        (or: NODE_PATH=/path/with/node_modules node js-crypto-oracle.js …)
 *
 * --key-format: passphrase (default for cryptojs — a *string* key means CryptoJS derives key+IV via
 * EVP_BytesToKey and emits the OpenSSL "Salted__" envelope) · utf8 · hex · b64 (these three mean raw
 * key bytes, and CryptoJS then REQUIRES an --iv for every mode except ECB).
 */
'use strict';

const fs = require('fs');

function die(msg) { process.stderr.write('js-crypto-oracle: ' + msg + '\n'); process.exit(1); }

const argv = process.argv.slice(2);
const action = argv[0];
if (!['dec', 'enc'].includes(action)) {
  die('first argument must be dec or enc (see the header of this file for usage)');
}
const opt = (name, dflt) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? argv[i + 1] : dflt;
};

const lib = (opt('lib', 'auto') || 'auto').toLowerCase();
const keyStr = opt('key');
const keyFormat = (opt('key-format', 'passphrase') || 'passphrase').toLowerCase();
const mode = (opt('mode', 'cbc') || 'cbc').toLowerCase();
const padding = (opt('padding', 'pkcs7') || 'pkcs7').toLowerCase();
const ivHex = opt('iv');
const file = opt('file');
const data = opt('data');

let input = data;
if (file) input = fs.readFileSync(file === '-' ? 0 : file, 'utf8');
if (input === undefined) input = fs.readFileSync(0, 'utf8');
input = String(input);

function need(name) {
  // node resolves modules relative to THIS file, but the library is usually installed wherever the
  // tester ran `npm i` — try the obvious places before giving up
  const path = require('path');
  const tries = [name, path.join(process.cwd(), 'node_modules', name)];
  for (const p of (process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean)) {
    tries.push(path.join(p, name));
  }
  const lookIn = opt('modules');
  if (lookIn) tries.unshift(path.join(lookIn, name), path.join(lookIn, 'node_modules', name));
  for (const t of tries) {
    try {
      return require(t);
    } catch (e) { /* next */ }
  }
  die('cannot load "' + name + '" from ' + tries.join(', ') + ' — run `npm i ' + name +
      '` (anywhere) and pass --modules <that dir>, or set NODE_PATH');
}

function guessLib(payload) {
  const t = payload.trim();
  if (t.startsWith('U2FsdGVkX1')) return 'cryptojs';        // base64("Salted__…")
  if (t.startsWith('{') && /"ct"\s*:/.test(t) && /"iv"\s*:/.test(t)) return 'sjcl';
  return 'cryptojs';
}

const chosen = lib === 'auto' ? guessLib(input) : lib;

if (chosen === 'sjcl') {
  const sjcl = need('sjcl');
  if (!keyStr) die('sjcl needs --key (its password/passphrase)');
  try {
    const out = action === 'dec' ? sjcl.decrypt(keyStr, input.trim())
                                 : sjcl.encrypt(keyStr, input);
    process.stdout.write(out);
  } catch (e) {
    die('sjcl failed: ' + e.message + ' (wrong password, or the envelope is not sjcl JSON)');
  }
  return;
}

if (chosen !== 'cryptojs') die('unknown --lib ' + chosen + ' (cryptojs | sjcl | auto)');

const C = need('crypto-js');
if (!keyStr) die('cryptojs needs --key');

const MODES = { cbc: C.mode.CBC, ecb: C.mode.ECB, ctr: C.mode.CTR, cfb: C.mode.CFB, ofb: C.mode.OFB };
const PADS = { pkcs7: C.pad.Pkcs7, none: C.pad.NoPadding, zero: C.pad.ZeroPadding,
               iso10126: C.pad.Iso10126, ansix923: C.pad.AnsiX923, iso97971: C.pad.Iso97971 };
if (!MODES[mode]) die('unknown --mode ' + mode);
if (!PADS[padding]) die('unknown --padding ' + padding);

function parseKey() {
  if (keyFormat === 'hex') return C.enc.Hex.parse(keyStr);
  if (keyFormat === 'b64' || keyFormat === 'base64') return C.enc.Base64.parse(keyStr);
  if (keyFormat === 'utf8') return C.enc.Utf8.parse(keyStr);
  return null;                                        // passphrase: hand the string to CryptoJS
}

const cfg = { mode: MODES[mode], padding: PADS[padding] };
const rawKey = parseKey();
if (rawKey && mode !== 'ecb') {
  if (!ivHex) {
    die('a raw key (--key-format ' + keyFormat + ') needs --iv for mode ' + mode +
        ' — CryptoJS has no zero-IV default, so the app passes an IV from somewhere: look for a ' +
        'literal next to the key, or a value prepended to the ciphertext');
  }
  cfg.iv = C.enc.Hex.parse(ivHex);
}

try {
  if (action === 'dec') {
    const pt = rawKey ? C.AES.decrypt(input.trim(), rawKey, cfg)
                      : C.AES.decrypt(input.trim(), keyStr, cfg);
    const text = pt.toString(C.enc.Utf8);
    if (!text) die('decrypted to nothing — wrong key, wrong key-format (passphrase vs raw), or the ' +
                   'payload is not a CryptoJS envelope');
    process.stdout.write(text);
  } else {
    const ct = rawKey ? C.AES.encrypt(input, rawKey, cfg)
                      : C.AES.encrypt(input, keyStr, cfg);
    process.stdout.write(ct.toString());
  }
} catch (e) {
  die('cryptojs failed: ' + e.message);
}
