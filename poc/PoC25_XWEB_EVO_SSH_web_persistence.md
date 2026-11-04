# PoC25 — XWEB EVO 5.8.8 HTTP-to-SSH root chain and web-account persistence

## Status

Validated as one sequence with the actual recovered ARM Lighttpd/Lua handlers and
Dropbear 2022.83 in a disposable network-disabled Docker/QEMU lab. No physical
controller, external network, or third-party address was contacted.

## Chain

1. An unauthenticated request to `cgi-bin/sysinfo.lua` returns the controller ID
   derived from the MAC address.
2. The MAC/date-derived daily code is accepted by unauthenticated
   `cgi-bin/api.lua` with `action=ssh` and `target=start`.
3. The real Dropbear service accepts `root` with `xwebdix` plus the same daily
   code. A command returns `uid=0(root)` and writes a fixed canary.
4. The root shell creates a synthetic regular user and full-permission profile
   using the vendor's JSON account schema in scratch `/opt/setup`.
5. The API stops Dropbear with `target=stop`.
6. The new account authenticates through the real `login.lua`, receives a
   session, and reads privileged account information through `users.lua`.

This converts temporary SSH root access into persistent web access that does not
require SSH to remain enabled. Account creation is a post-exploitation
persistence step, not an independent authentication bypass.

## Runtime evidence

Reproduce the isolated test with:

```bash
python3 lab/evo-arm-ssh-chain-canary.py
```

The harness uses only the documentation MAC `00:11:22:33:44:55`, synthetic daily
credentials, a lab-only account, and writable scratch directories. It removes
its container and does not modify a physical controller.

Verified result:

```text
public sysinfo ID: 001122334455
API: {"SSH":"start"}
uid=0(root) gid=0(root) groups=0(root)
LAB_USER_CREATED
API: {"SSH":"stop"}
lab user login after SSH stop: ok
lab user ID: 2
lab profile ID: 99
privileged user information: validated
```

Machine-readable evidence:
`results/evo-5.8.8-dropbear-shell-validation.json` for the standalone Dropbear
component and `results/evo-5.8.8-http-ssh-root-chain-validation.json` for the
complete sequence.

## Boundaries

- The MAC, credentials, account, and full-permission profile are synthetic lab
  values. The account is a full-permission regular user, not the special
  `Administrator` account.
- Physical firewall behavior, service startup timing, and device reachability
  remain unverified.
- BusyBox applet links and runtime libraries were supplied only where the
  derived lab rootfs omitted them. The vendor Lua handlers, Dropbear,
  authentication logic, and account format were not changed.
- This result does not demonstrate access to XWEB Pro 1.16.1, whose executable
  components remain encrypted.

## Impact and remediation

An attacker who obtains temporary root access through the daily-credential
chain can create a lower-visibility web account and stop SSH, reducing reliance
on the original access path and making subsequent privileged actions available
through the normal web interface.

- Remove public MAC/date-derived credentials and require unique random
  credentials or key-only administration.
- Require an authorized administrative session for SSH start/stop actions.
- Disable root SSH login and run web services with least privilege.
- Audit `/opt/setup/users` and `/opt/setup/profiles` for unauthorized changes,
  unexpected accounts, and broad permission assignments.
- Alert on SSH enablement followed by account or profile changes, and revoke
  unauthorized sessions and accounts during incident response.
