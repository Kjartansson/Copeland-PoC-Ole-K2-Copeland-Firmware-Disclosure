# XWEB3000/5000 EVO 5.8.8 i686 security assessment

## Summary

A newly listed official x86 EVO 5.8.8 package was recovered and executed in an
isolated QEMU/bubblewrap lab. The genuine web handlers and native updater were
tested with synthetic accounts, a loopback-only fake update server, and harmless
canaries. No physical controller, third-party target, or personal remote-device
artifact was used.

The highest-impact result is a self-edit authorization flaw that lets any
authenticated account execute operating-system commands as root. Separate tests
also confirmed unsigned update-command execution, arbitrary file writes,
memory-corruption crashes, stored-image placement, and a script-breakout XSS.

## Official artifact

- Catalog: https://webapps.copeland.com/Dixell/Pages/XWEB3000_5000_EVO
- Package: https://webapps.copeland.com/dixell/Content/Pages/SystemSoftwareUpdate/XWEB30005000-EVO/XWEB_EVO_5.8.8.STANDARD.24-25902d_3000_5000_LIB20241125.zip
- Size: 25,722,342 bytes
- SHA-256: `fda55eef4620bd5e7008febef0c7a3ccf4c22957a53a822a47c62dd89b3ad47c`
- Acquired: 2026-11-20

`tools/xweb_evo_xor_extract.py` decoded both RPMs and XML descriptors. The EVO
payload produced 995 safe members and FCEVO produced 898. FCEVO is the RPM-based
OS variant without local kiosk/browser launch code; it shares the web interface
and is not a separate release. The original archive is not redistributed.

## Findings

| PoC | Finding | Validated scope |
|---|---|---|
| [PoC28](../poc/PoC28_XWEB_EVO_self_edit_root_command_injection.md) | Any authenticated user can execute root commands through self-edit `username` | Genuine HTTP handler; other-user/profile denials, root-mapped `id`, cleanup |
| [PoC29](../poc/PoC29_XWEB_EVO_locale_traversal.md) | `languages-edit` locale-tag traversal writes/deletes `.json` files outside the locale directory | Genuine handler with role and no-role controls |
| [PoC30](../poc/PoC30_XWEB_EVO_unsigned_update_command_execution.md) | Unsigned update metadata executes commands | Genuine updater and fabricated loopback repository; no RPM/reboot/firmware write |
| [PoC31](../poc/PoC31_XWEB_EVO_image_upload_authorization.md) | Any authenticated user can upload/delete SVG/images | Real multipart upload, stored-content check, deletion and no-session control |
| [PoC32](../poc/PoC32_XWEB_EVO_doevo_xss_specialuser.md) | Script-breakout XSS and forgeable `SpecialUser` feature token | Genuine `doevo.cgi`; token is not a standalone login bypass |
| [PoC33](../poc/PoC33_XWEB_EVO_native_upload_parser.md) | Native `finalfile` arbitrary write, multipart memory-corruption crashes, and limited pre-auth staging | Genuine native parser; exact boundaries and negative controls |

### Self-edit root command injection

`users.lua:200-231` allows self-edit without `system/users-edit`, but its
forbidden fields omit `username`. `lualib_users.lua:561-576` concatenates that
username into a shell `find` command. A quote breakout executes shell syntax.
A restore-only account obtained `{"status":"ok"}` and real `uid=0(root)` output
in the root-mapped harness. Other-user and profile-change controls were denied.
The genuine systemd/Lighttpd configuration also runs CGI as root.

### Locale traversal

`langman.lua` checks `tools/languages-edit` but does not constrain locale tags.
`lualib_languages.lua` appends attacker-controlled tags to the locale path for
write/delete operations. A role-restricted session wrote and deleted a canary
outside that directory; the same request without the role was denied. Write and
delete are suffix-constrained to `.json`.

### Unsigned update commands

The updater uses repeating-XOR obfuscation derived from the filename, not a
signature. Its XML metadata supports arbitrary command templates. The genuine
`new_xwrpm.cgi` accepted a wholly fabricated unsigned manifest and payload from
loopback and executed a harmless command. Its session gate is a session-file
`stat()` check; no update-specific permission was observed in that flow. This is
an authenticated update-path result, not a claim of unauthenticated Internet
compromise or a completed firmware installation.

### Image authorization

`images.lua` checks only whether a session is valid. A restore-only account
uploaded a real SVG, verified the stored content, and deleted it. An
unauthenticated control was denied. Browser execution of SVG active content was
not tested.

### `doevo.cgi`

The index handler reflects request data into a JavaScript string using a
blacklist rather than contextual encoding. A marker containing
`</script><script src=...>` was emitted verbatim. Exploitation requires a route
without the blacklisted `cgi-bin` substring; the index and `SpecialUser` aliases
provide such routes.

The `SpecialUser` `art` token is MD5 of `HTTP_HOST-unixtime`, accepted within a
small time window. A valid token changes only `INITPARAM`, pre-arming a feature
for a later valid login. It does not create a session or grant content alone.

### Native upload parser

The parameters flow's hidden `finalfile` parameter traverses outside the upload
directory and writes attacker-controlled plaintext. Separate overlong multipart
filename and documents `input` values caused genuine SIGSEGV/HTTP 500 results;
code execution is not claimed. `evoupfile` and `evoupfilec` can also leave a
basename-normalized file in `/opt/tmp/upl` before an unauthenticated denial.

## Other evidence

See [PoC34](../poc/PoC34_XWEB_EVO_shared_credentials_tls_key.md) for the shared
credential and TLS-key verification steps.

Both EVO and FCEVO verify the shipped `dixell:dixell` credential and contain the
same TLS private key/certificate. FCEVO explicitly permits root SSH login. The
predictable daily root-password chain must therefore not be treated as strong
authentication. These are configuration/credential findings, not a physical SSH
test performed for this report.

All ten earlier x86 validators passed on 5.8.8. This regression result is not a
claim that those older findings are new.

## PRO and E3 boundary

EVO's filename-derived XOR scheme does not decode XWEB PRO `Salted__` payloads,
and no PRO updater or PRO private key was found in this package. PRO uses a
different detached-signature envelope, so the unsigned EVO update result must
not be transferred to PRO. No E3/Site Supervisor plaintext or exploit is claimed.

## Reproduction and privacy

The `lab/` launchers and validators reproduce the isolated tests with
operator-supplied official firmware. `tools/xweb_evo_remote.py` provides
authorization-gated remote-safe checks for suitable cases. Destructive factory,
firmware-write, persistence, and real reboot paths remain lab-only.

Raw runtimes and evidence are intentionally omitted from this public repository.
Only synthetic accounts, documentation addresses, and generalized technical
evidence are published. No personal remote-device identifiers, configurations,
credentials, sessions, or captures are included.
