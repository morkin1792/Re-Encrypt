# Installing this skill

This folder is self-contained: **copy it into `.claude/skills/` and it works** in any Claude Code
session opened in that directory. Nothing here refers to the repository it came from.

```bash
# per project (the copy is what makes it independent of where you cloned this from)
mkdir -p <project>/.claude/skills
cp -r decrypt-app-traffic <project>/.claude/skills/

# or for every project
cp -r decrypt-app-traffic ~/.claude/skills/
```

Start a **new session** in that directory afterwards — skills are discovered at session start.
Then invoke it by name (`/decrypt-app-traffic <apps-dir>`) or just describe the problem
("the request bodies from these APKs are encrypted, work out how").

**Keep the folder named `decrypt-app-traffic`.** Claude Code expects the directory name to match the
`name:` field in `SKILL.md`'s frontmatter, so if you do rename the folder, change that field to match.
Nothing else inside depends on the name: the scripts locate each other relatively, and `SKILL.md`
finds its own directory by looking for a file that only exists here, whatever the folder is called.

**Codex:** the same folder works as a plugin skill. Place it under a `skills/` directory that sits
next to a `.codex-plugin/plugin.json` (the bundle this came from has one), then:

```bash
codex plugin marketplace add <that bundle directory>
codex plugin add re-encrypt-skill@re-encrypt-skill
```

## Requirements

Python 3.9+ only. Everything else degrades with a clear message:

| For | Needs | Without it |
|---|---|---|
| artifact triage, traffic analysis | nothing (stdlib) | — |
| AES-CBC/CTR/ECB/CFB/OFB, RSA | `openssl` on PATH | `pip install pycryptodome` |
| AES-GCM, ~5× faster key sweeps | `pycryptodome` or `cryptography` | error naming the package |
| the app's-own-library oracle | `node` + `npm i crypto-js sjcl` | `crypto-cli.py` covers the common envelopes |
| reading decompiled code | `jadx` / `apktool` | triage still names the classes and the literals |
| runtime hooking (last resort) | `frida-tools`, a device | the other three rungs need none of it |

Check the crypto side in one line:

```bash
python3 scripts/crypto-cli.py selftest
```

## Try it without a real app

```bash
python3 testdata/make-fixtures.py /tmp/skilltest --answers
```

Three fake apps whose traffic is encrypted with the real algorithms, one per rung of the key ladder:
a hardcoded AES key in the DEX, a CryptoJS **passphrase** (the literal is not the key), and a session
key that exists only in a handshake — the last one *must not* be solvable from the artifact. Point the
skill at `/tmp/skilltest/apps`; the matching traffic is in `/tmp/skilltest/traffic`.
`ANSWERS.md` holds the expected outcome — read it after the run, not before.
