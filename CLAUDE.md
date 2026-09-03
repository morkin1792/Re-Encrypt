# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**Re:Encrypt** is a Burp Suite extension (Montoya API) that decrypts/re-encrypts custom-encrypted HTTP traffic on the fly across Proxy, Repeater, and Intruder. For each match it either runs user-supplied shell commands or a built-in crypto engine.

Requires Java 21+ and Burp Suite v2024.x+ (target Montoya API `2025.8`).

## Build & Test

```bash
./gradlew build          # compiles, tests, and produces the loadable jar via shadowJar
./gradlew shadowJar      # build the jar only -> app/build/libs/re-encrypt.jar
./gradlew test           # run all JUnit 5 tests

# single test class / method
./gradlew test --tests "reencrypt.ShellCommandTest"
./gradlew test --tests "reencrypt.ShellCommandTest.testExecute_Echo_Normal"
```

- Single-module Gradle project (the module is `app`); `settings.gradle.kts` names the root `ReEncrypt`.
- The standard `jar` task is **disabled**; only `shadowJar` produces output. The shadow plugin is required because `net.openhft:zero-allocation-hashing` must be relocated (to `reencrypt.shaded.hashing`) to work inside Burp.
- The loadable artifact is always `app/build/libs/re-encrypt.jar`. Load it via Burp **Extensions > Installed > Add**.
- `reencrypt.App` is set as `mainClass`/`Main-Class` only to satisfy the application plugin; the real entry point is `App.initialize(MontoyaApi)`, which Burp calls.
- Tests that depend on POSIX shell behavior early-return on Windows (`os.name` check) rather than asserting.

## Architecture

`App.initialize()` is the single wiring point. It constructs one `Config` and one `ReEncrypt`, then registers **five** integration surfaces — keep this list in mind when a behavior change must apply everywhere:

| Surface | Class | Role |
|---|---|---|
| Suite config tab | `ui.SettingsTab` | The "Re:Encrypt" tab; defines patterns + all settings |
| Request/Response editor tabs | `ui.RequestTab` / `ui.ResponseTab` → `ui.RequestResponseTab` | Per-message custom editor (Repeater/Proxy): decrypts on display, re-encrypts on send |
| Proxy patching | `ProxyHandler` | "Patch proxy": decrypt+re-encrypt in-flight for patterns with `patchProxy` on |
| Intruder auto en/decrypt | `IntruderHandler` (`HttpHandler`) | Encrypts Intruder requests / decrypts Intruder responses |
| Intruder payload processor | `IntruderPayloadProcessor` | Encrypts individual payloads |

### Core flow (`ReEncrypt`)

`ReEncrypt` is the orchestration brain shared by all surfaces. The central contract:

- **Every capture regex must contain capturing group 1.** `searchPattern()` returns `matcher.start(1)/end(1)`; that span is the exact byte range extracted and later replaced. `PatternType.buildRegex()` generates these regexes (the group is the captured value) from friendly inputs (Header / URL param / JSON param / Whole Body / Custom Regex).
- `searchAndDecrypt` → finds the ciphertext span, decrypts it (with cache fallback), optionally logs.
- `encryptAndPatch` → re-encrypts plaintext and splices it back via `patchRequest` (raw byte array surgery, not Burp body APIs).
- `matchReplace` → replaces a span without crypto (used to show plaintext in read-only views).

### Pattern model (`CapturePattern`)

The unit of configuration, stored in two lists (request / response) on `Config`. A pattern operates in one of two **mutually exclusive** modes, switched by `usesEngine()` (i.e. `engineId != null`):

1. **Custom command mode** — runs `decCommand` / `encCommand` through `ShellCommand`.
2. **Engine mode** — uses a built-in `CryptoEngine` (`engineId` + flat `engineParams` map).

`CapturePattern` is a plain POJO persisted as JSON via `ConfigJson` (see below) — it is deliberately **not** `Serializable`. Note the multiple constructors, including a legacy one kept for callers. Targeting is decided by `isTarget()` (Burp project scope, or `urlTargetRegex`, or match-all when empty).

### Persistence and config transfer (`ConfigJson`, `ui.PatternIo`, `AutoLoader`)

One JSON format serves both Re:Encrypt's own persistence and the export/import files, so the exchange
code is exercised on every save instead of only when someone clicks Export.

- `ConfigJson.listToJson` / `listFromJson` — one pattern list, used for persistence (the request/response
  split is the storage key, so no `isRequest` field is written).
- `ConfigJson.toFile` / `fromFile` — exchange files: `{"reencrypt":1,"exported":…,"patterns":[…],"settings":{…}}`.
  Each pattern carries `isRequest` but **no `enabled`**: whether a pattern runs is the importer's
  call (the import dialog's checkbox), and `fromNode` defaults it to true so auto-load — which has no
  prompt — takes effect. `settings` is omitted by a patterns-only export. Unknown keys are
  ignored; a bad entry is skipped and reported in `ImportResult.errors` rather than failing the file.
- **Exporting downgrades "Project In-Scope" to "Everything"** — that scope resolves against the receiving
  Burp project's Target scope, which a file cannot carry.
- `ui.PatternIo` — the file choosers, the import review dialog (which shows each pattern's decrypt
  command, the only place the user sees what code an import will run) and the collision policy.
- `AutoLoader` — optional mtime poll on one file, replacing the whole pattern set on each change so a
  producer can delete patterns. Its `settings` block is ignored.

JSON comes from **Gson, shaded to `reencrypt.shaded.gson`**. Montoya ships a JSON API but it is backed
by an `ObjectFactoryLocator.FACTORY` that only Burp populates, so it is null under unit tests and would
make persistence untestable.

### Crypto engine layer (`reencrypt.engine`)

Pluggable built-in crypto, an alternative to shell commands. To add an engine: implement `CryptoEngine` (`encrypt`/`decrypt`/`validate` over a flat `Map<String,String>` params, plus a `createConfigPanel`), register it in `CryptoEngineRegistry`'s static block, and provide a matching `ui.EngineConfigPanel` subclass. The registry's order drives the UI dropdown; `getDropdownNames()` always prefixes `"Custom Command"`. Existing engines: `AesEngine` (CBC/ECB/GCM/CTR/CFB/OFB; raw / iv+ct / iv+ct+tag / OpenSSL / JWE structures) and `RsaEngine`. Shared helpers: `EncodingUtils`, `KeyLoader`.

### Shell command execution (`ShellCommand`)

Runs `bash -c` (POSIX) or `cmd.exe /c` (Windows). Two placeholders substitute the captured data: `{DATA}` (inline) and `{FILE}` (path to a temp file, auto-deleted, created owner-readable only since it holds plaintext). **Exactly one trailing newline is stripped** (`\r\n` or `\n`) to absorb `echo`-style output while preserving other whitespace — `ShellCommandTest` pins this behavior.

Two execution paths: `execute()` merges stderr into stdout so command errors surface in the editor tab, while `executeRawChecked()` (binary output, e.g. DER key bytes for `KeyLoader`) keeps stderr **out** of the returned bytes — a command that exits 0 while printing a warning would otherwise corrupt the key material — and redirects it to a file, reporting it only on a non-zero exit.

### Result & caching

- `OperationResult` carries output + exit code + cache flags. `getOutputCheckingExitCode()` throws `CommandException` on non-zero exit; `isCached()` marks results served from cache after a command failure.
- `DecryptionCache` is a persistent ciphertext→plaintext map keyed by an XXH3 64-bit hash (`Utils.getHash`), enabled per-pattern via `useCacheSystem`. When a decrypt command fails but a cached value exists, surfaces fall back to it and annotate the message.

### Conventions / gotchas

- Handlers compare an XXH3 hash of content before vs. after patching and only replace the message when it changed; they also recompute `Content-Length` on the new request/response.
- Editors read/write bytes using the `Windows-1252` charset to round-trip binary faithfully (see `RequestResponseTab.setBytes`).
- `Config.checkReloadEditors()` is a consume-once flag that tells editor tabs to rebuild after pattern edits.
- Persisted state lives in Burp's `PersistedObject` (`persistence().extensionData()`), not files — except the human-readable activity log written to `~/reencrypt.log` (path configurable).
- `Config` records load failures in `getLoadErrors()`; `App` reports them via `logging().logToError()` so unreadable stored config is visible instead of silently producing an empty table.
