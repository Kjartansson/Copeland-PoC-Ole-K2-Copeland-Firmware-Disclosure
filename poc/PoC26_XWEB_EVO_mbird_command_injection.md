# PoC26 — XWEB EVO 5.8.8 MessageBird settings-edit to root command execution

## Status

Validated with actual EVO 5.8.8 ARM `systemsetup.lua` and `utility.lua` handlers
in a network-disabled Docker/QEMU lab. No physical controller or external
network was used. The account and profile are synthetic.

## Vulnerability

`systemsetup.lua` permits a user with `system/settings-edit` to store arbitrary
`Sms/MbirdBal` and `Sms/MbirdCode` values. `utility.lua` later concatenates
those values into a shell command without quoting:

```lua
local response = io.popen('curl -X GET '..url..' -H "Authorization: AccessKey '..code..'" --insecure 2>/dev/null'):read()
```

A URL containing shell separators therefore becomes a stored command-injection
payload when `action=mbirdbalance` is requested. This is separate from the
Administrator-only debug terminal.

## Runtime proof

Reproduce with:

```bash
EVO_MBIRD_TEST=1 python3 lab/evo-arm-ssh-chain-canary.py
```

The harness creates a regular account whose only nonzero permission is
`settings-edit`. It first confirms that the Administrator debug terminal denies
the account, then stores a canary URL and triggers `mbirdbalance`.

Observed results:

```text
Administrator terminal: PERMISSION_DENIED
settings-edit response: status ok
canary: EVO_MBIRD_CANARY
command output: uid=0(root) gid=0(root) groups=0(root)
```

Machine-readable evidence: `results/evo-5.8.8-mbird-command-injection.json`.

## Impact and boundary

A non-Administrator with permission to edit system settings can execute shell
commands as the web service's user. In the isolated runtime, that user is root.
This is an authenticated privilege-escalation path, not an unauthenticated RCE.
Physical-device reachability and process ownership were not tested.

## Remediation

- Do not invoke a shell for the balance request. Use an HTTP client library or a
  fixed argument-array process API with no command interpreter.
- Validate the URL against an explicit HTTPS scheme and host allowlist; reject
  shell metacharacters and control characters in URL and access-key fields.
- Remove `--insecure` and require certificate validation.
- Run the web service and helper processes with least privilege, even when all
  input is correctly validated.
- Add a regression test proving that a `settings-edit` user cannot execute a
  second command or write outside an approved temporary directory.
