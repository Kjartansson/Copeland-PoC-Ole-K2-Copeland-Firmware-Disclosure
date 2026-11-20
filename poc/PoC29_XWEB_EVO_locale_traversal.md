# PoC29 — XWEB EVO locale-tag path traversal (arbitrary JSON write / file delete)

## Status

Dynamically validated with official vendor Lighttpd/Lua code in an isolated
QEMU/bubblewrap lab, and re-validated with the public authorization-gated
remote checker against the same loopback runtime. No physical controller or
third-party address was contacted.

- XWEB3000/5000 EVO 5.8.8 i686: confirmed over loopback HTTP.
- A session with the `tools/languages-edit` permission is required. The same
  request from a session without that role returned `PERMISSION_DENIED` and
  wrote nothing; this is not an unauthenticated or permission-bypass finding.
- EVO reached End of Support in March 2026. Physical reachability and the
  device-side filesystem impact on a controller remain unverified.

## Root cause

`langman.lua:17-25` checks a valid session and `tools/languages-edit`, but
never validates the locale `tag`. `lualib_core.lua:89` builds the locale path
as `LOCALES_CUSTOM_DIR..'/%s.json'`, and `lualib_languages.lua` passes the
attacker-controlled tag straight into filesystem calls:

- `lualib_languages.lua:99-121` (`Languages.add_locale`): `io.open(path, 'w')`
- `lualib_languages.lua:136-149` (`Languages.remove_locale`): `os.remove(path)`
- `lualib_languages.lua:155-180` (clone/export paths use the same construction)

A tag such as `../../../opt/tmp/<session>/<name>` therefore resolves outside
`/opt/setup/locales/`. The write is suffix-constrained to `.json` with
partially controlled JSON content (a cloned locale with attacker-controlled
metadata); deletion is not content-limited and removes any file whose
`<tag>.json` path resolves.

## Harmless proof

The remote checker uses a unique tag pointing into the session's own
temporary area, which the genuine session code creates at login
(`lualib_session.lua:65-66`):

```text
tag   = ../../../opt/tmp/<session>/evopoc_<random>
label = EVOPOC<random>
```

Because no HTTP endpoint reliably returns files from that directory, the proof
is behavioral and exact:

1. `action=add` returns `{"status":"ok"}` — the traversal path was accepted and
   `/opt/tmp/<session>/evopoc_<random>.json` was written outside the locale
   tree.
2. A repeated `action=add` with the same tag returns
   `{"status":"error","error":"ALREADY_EXISTS"}` — remote readback that the
   file exists at the traversed location.
3. `action=remove` returns `{"status":"ok"}` — deletion through the same sink.
4. A third `action=add` returns `{"status":"ok"}` again (instead of
   `ALREADY_EXISTS`) — confirms the delete, after which a final `remove`
   cleans up.

A role-restricted control session receives `PERMISSION_DENIED` at step 1 and
creates nothing.

## Reproduce (authorized remote check)

Run only against a device you own and may modify, with an account that holds
`tools/languages-edit`:

```bash
cd /path/to/Ole-K2-Copeland-Firmware-Disclosure
python3 tools/xweb_evo_remote.py --authorized \
  --username <your-user> --password <your-password> \
  locale http://<your-device>
```

The loopback-only lab validator is
`lab/evo-x86-5.8.8-locale-traversal-test.sh` (via `lab/run-evo-x86-5.8.8.sh`).

## Expected sanitized result

With the permission:

```json
{
  "confirmed": true,
  "add_status": "ok",
  "readd_status": "ALREADY_EXISTS",
  "remote_readback": true,
  "remove_status": "ok",
  "delete_confirmed": true,
  "canary_deleted": true,
  "exit_code": 0
}
```

Without the permission the check reports `"add_status": "PERMISSION_DENIED"`,
`"confirmed": false`, exit code 1 — the permission gate working as intended.
Output contains no target address, credentials, session token, MAC/IP, or raw
device response.

## Cleanup

The checker deletes the canary through the same API in a `finally` path and
verifies deletion; exit code 5 with `"canary_deleted": false` means the
`evopoc_*.json` file may remain under the session's `/opt/tmp/<session>/`
directory and should be removed manually (the directory is normally reclaimed
at logout).

## Impact and boundaries

A `languages-edit` holder can write `.json` files with partially controlled
content, and delete arbitrary files by resolved path, anywhere the web process
can write — including configuration and profile files on a real device. On the
physical controller the web process runs as root (see PoC28), but device-side
effect was not observed on hardware. The checker's canary never leaves the
caller's own session temp area.

## Remediation

- Accept only a strict locale-tag grammar (for example
  `^[a-z]{2}(-[A-Z]{2})?$`); reject path separators and dot segments.
- Resolve the final path and verify it stays beneath the locale directory
  before every open/remove, for add, remove, clone, import, and export alike.
- Replace shell/filesystem string composition with safe path-join APIs.
- Add regression tests for `../` tags, absolute tags, encoded separators, and
  sessions without `tools/languages-edit`; deny them by default.
