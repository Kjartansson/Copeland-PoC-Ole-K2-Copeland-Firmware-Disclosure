# PoC27 — XWEB EVO email-test msmtp configuration injection

## Status

Validated with the genuine EVO 5.8.7 i686 Lighttpd/Lua `email.lua` handler and
real `msmtp` 1.8.32 in a network-disabled bubblewrap/QEMU lab. The 5.8.8 ARM
handler is byte-identical, but only the i686 handler was executed in this test.
No physical controller or external network was used. The account and profile
are synthetic.

## Vulnerability

`email.lua` requires a valid session with `system/settings-edit`. It accepts
SMTP `server_username` and `server_password` values, URI-decodes them, and
writes them directly into `/dev/shm/email_test.conf` without rejecting newline
or configuration-directive syntax. It then invokes `msmtp` with that file.
Sources: `extracted/EVOPackage_5.8.7_package/opt/www/cgi-bin/email.lua:20-35,59-60,85`
and the byte-identical
`extracted/XWEB_EVO_5.8.8_ARM_package/opt/www/cgi-bin/email.lua`.

A `server_password` beginning with a newline produces an empty ordinary
`password` directive followed by an attacker-supplied `passwordeval` directive.
Real `msmtp` accepts both lines and executes the `passwordeval` command. A
nonempty ordinary password takes precedence and does not reach the injected
command, so the empty first line is part of the working path.

This is authenticated command injection through configuration-file syntax, not
shell metacharacter injection into the `msmtp` command line. The recipient and
system-email address patterns reject shell metacharacters and are not the
injection vector.

## Runtime proof

Reproduce with:

```bash
EVO_EMAIL_TEST=1 ./lab/run-evo-x86.sh
```

The validator uses an account whose only permission is
`system/settings-edit`. It verifies that an unauthenticated request is denied
and that the same account cannot reach the Administrator debug terminal. It
then submits a `server_password` containing a newline and a `passwordeval`
command that writes a fixed canary and records `id` output.

Observed results:

```text
PASS no-session request denied
PASS settings-edit-only account authenticated
PASS Administrator terminal denied
PASS genuine msmtp passwordeval executed as the web-service user
overall: PASS
```

The canary contains `EVO_EMAIL_CANARY`. The command executed as `uid=1000`, the
web-service user in this i686 lab. The HTTP report may remain `status:
unknown` because no SMTP server is listening; command execution occurs before
the SMTP connection completes.

## Impact and boundaries

A non-Administrator allowed to edit system settings can execute operating-system
commands as the web-service user, exceeding the intended configuration-only
capability. This is not an unauthenticated vulnerability and root execution is
not claimed.

The lab starts Lighttpd with umask `077`, making the generated credentials file
owner-only as required by `msmtp`. The recovered controller package does not
include an `msmtp` executable, so the test uses the local 1.8.32 compatibility
runtime. Physical-device `msmtp` version, service umask, process ownership, and
network reachability remain unverified. Byte-identical 5.8.8 source supports
static transfer only, not a second dynamic-device claim.

## Remediation

- Reject carriage returns, newlines, NULs, and other control characters in every
  SMTP configuration field, including username, password, host, and port.
- Do not generate an executable configuration language from untrusted text.
  Prefer a fixed argument-array process API or a configuration serializer that
  cannot introduce new directives.
- Disable `passwordeval` and other command-execution features in the deployed
  `msmtp` build or wrapper when they are not required.
- Keep credential files owner-only with mode `0600`, while recognizing that
  file permissions alone do not prevent directive injection.
- Run the web service and mail helper with least privilege.
- Add regression tests proving that a `settings-edit` user cannot add
  `passwordeval`, execute a second command, or write outside an approved
  temporary directory.
