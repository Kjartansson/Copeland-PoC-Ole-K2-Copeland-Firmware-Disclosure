# PoC28 — XWEB EVO any-user self-edit root command injection

## Status

Dynamically validated with official vendor Lighttpd/Lua code in an isolated
QEMU/bubblewrap lab, and re-validated end to end with the public
authorization-gated remote checker against the same loopback runtime. No
physical controller or third-party address was contacted.

- XWEB3000/5000 EVO 5.8.8 i686: confirmed over loopback HTTP with a genuine
  session.
- Any authenticated account is sufficient. A profile granting only
  `system/restore` (no user-administration rights) was used; this is not an
  unauthenticated finding.
- In the root-mapped harness the injected command produced `uid=0(root)`. The
  genuine `lib/systemd/system/lighttpd.service` sets no `User=`/`Group=` and
  `etc/lighttpd/lighttpd.conf` leaves privilege dropping commented out, so the
  device CGI runs as root. Root context was emulated with bubblewrap, not
  confirmed on physical hardware.
- EVO reached End of Support in March 2026. Physical reachability and process
  privileges on a controller remain unverified.

## Root cause

`users.lua:200-231` permits a user without the `system/users-edit` permission
to edit their own account. The forbidden-field list (`profile`,
`password_expiration`, `enabled`, `expiration_date`) does not include
`username`. `lualib_users.lua:561-576` then concatenates the attacker-controlled
username into a shell command:

```lua
local fd = io.popen('find /opt/setup/users/ -maxdepth 2 -type f -name "'..tostring(settings.config.username)..'"')
```

A double-quote breakout executes arbitrary shell syntax. The same username
later reaches `touch_file` (`lualib_core.lua:440-443`), a second
`os.execute('touch "<path>"')` sink, so the payload runs twice per edit.

## Harmless proof

The remote checker sets its own username to a uniquely generated value of the
form:

```text
x"; id > /opt/setup/images/evopoc_<random>.txt; echo EVOPOC<random> >> /opt/setup/images/evopoc_<random>.txt; rm -f /opt/setup/users/<id>/x; #
```

The injected command prints nothing to stdout (stdout would be mistaken for an
existing user file and the edit would be rejected), writes a uniquely named
harmless canary into the image directory, and removes the stray marker file the
vulnerable code creates. The canary is retrievable without any session through
the static `/imgimage/` alias, with the authenticated `images.lua list` action
as a fallback observation path.

Negative controls validated in the lab: editing a different user's account is
denied (`PERMISSION_DENIED`), and changing the `profile` field through
self-edit is denied.

## Reproduce (authorized remote check)

Run only against a device you own and may modify:

```bash
cd /path/to/Ole-K2-Copeland-Firmware-Disclosure
python3 tools/xweb_evo_remote.py --authorized \
  --username <your-user> --password <your-password> \
  self-edit http://<your-device>
```

`--user-id` overrides automatic discovery of the caller's numeric user id;
credentials may also come from `XWEB_EVO_USERNAME`/`XWEB_EVO_PASSWORD` or an
interactive prompt. The loopback-only lab validator is
`lab/evo-x86-5.8.8-self-edit-test.sh` (via `lab/run-evo-x86-5.8.8.sh`).

## Expected sanitized result

```json
{
  "confirmed": true,
  "edit_status": "ok",
  "proof": "canary with marker and uid= output retrieved via /imgimage/",
  "username_restored": true,
  "canary_deleted": true,
  "logged_out": true,
  "exit_code": 0
}
```

Output contains no target address, credentials, session token, MAC/IP, or raw
device response.

## Cleanup

The checker always restores the original username and deletes the canary in a
`finally` path, and logs out. Exit code 5 with
`"username_restored": false` or `"canary_deleted": false` means device state
may remain and should be removed manually (re-run the check, or delete the
`evopoc_*.txt` file through `images.lua`).

## Impact and boundaries

Any authenticated user, including the least-privileged role, can execute
operating-system commands as the web-service user (root per the shipped
service configuration). The lab used synthetic accounts; a real deployment's
profile permission matrix was not enumerated, and physical-device root
execution, while indicated by the shipped configuration, was not observed on
hardware.

## Remediation

- Validate usernames against a strict account-name allowlist before any use.
- Replace the shell-based existence check and `touch` helper with native
  filesystem APIs; never pass user-controlled data through a shell.
- Include `username` in the self-edit forbidden-field list, or require
  `system/users-edit` for username changes.
- Run the web service as a dedicated unprivileged user (`User=`/`Group=` in
  the unit file) so a handler flaw is not automatically root.
- Add regression tests for quote breakout, self-edit of other accounts, and
  forbidden-field changes; deny them by default.
