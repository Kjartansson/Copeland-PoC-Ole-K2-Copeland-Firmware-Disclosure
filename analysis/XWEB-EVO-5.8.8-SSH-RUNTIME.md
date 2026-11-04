# XWEB EVO 5.8.8 SSH chain — isolated ARM runtime verification

## Result

The actual recovered 5.8.8 `api.lua` and `sysinfo.lua` were executed in an
isolated ARM bubblewrap/QEMU environment. The recovered Dropbear was also tested
in a network-disabled Docker/QEMU ARM container. Public MAC disclosure, API
start/stop, password authentication, and a root-shell canary are now verified as
components. Physical-device connectivity and a single end-to-end request
sequence remain untested.

No external network request was made and no controller was contacted.

## Environment

- Genuine EVO 5.8.8 ARM package under the original Copeland research tree.
- Debian ARM Lua 5.1.5 interpreter with vendor Lua sources and libraries.
- Unchanged `api.lua` and `sysinfo.lua`.
- Minimal runtime configuration and an empty `libxwfunc` compatibility stub for
  the SSH-only action. `libconfig` was stubbed only for the sysinfo run.
- The Dropbear init script was replaced with a recorder, never a real service.
- A synthetic `ip` command returned only documentation MAC/IP values.

The `/bin/sh` symlink was replaced with the real BusyBox binary because QEMU
otherwise returned empty subprocess output. After that correction, the genuine
`xwpasswd` subprocess returned `H5FOG1`, matching its direct QEMU invocation.

## Verified behavior

Machine-readable result: `results/evo-5.8.8-api-arm-runtime.json`.

### Public system information

With no session supplied, the real `sysinfo.lua` returned `status: ok` and:

```json
{
  "id": "001122334455",
  "model_type": "XWEB300D",
  "release": "5.8.8.STANDARD.24--25902d",
  "timezone": "Europe/Rome"
}
```

The ID came from the synthetic `ip` stub. This verifies that the script's public
response path includes the MAC field; it is not a claim about a real device's
address.

### Wrong password rejected

Request body with `action=ssh`, `password=WRONG`, and `target=start` returned:

```json
{"status":"error","error":"PERMISSION_DENIED"}
```

The init recorder was not called.

### Correct password starts and stops SSH

With the actual code produced by the local `xwpasswd` subprocess:

```json
{"SSH":"start"}
{"SSH":"stop"}
```

The recorder contained exactly:

```text
start
stop
```

This verifies real password comparison, action dispatch, and init-script
execution in the recovered API code.

## Actual Dropbear authentication and root shell

The first bubblewrap test verified password authentication but could not change
groups in its restricted user namespace. The replacement
`lab/evo-arm-dropbear-canary.py` uses a disposable Docker container with
`--network none`, the recovered ARM rootfs, static QEMU, synthetic account data,
and a fixed host key. It does not alter Dropbear or its authentication logic.

With the documentation-only password `xwebdixO0ANI3`, the genuine Dropbear
2022.83 service completed authentication, executed the requested shell command,
and returned:

```text
uid=0(root) gid=0(root) groups=0(root)
EVO_SSH_ROOT_CANARY
```

The canary was independently read from the scratch filesystem and the container
was removed. See `results/evo-5.8.8-dropbear-shell-validation.json` and
`build/evo-dropbear-runtime/`. This verifies the credential, real SSH service,
root shell, and file-write primitive in the isolated runtime.

## Combined HTTP-to-SSH and web-persistence sequence

`lab/evo-arm-ssh-chain-canary.py` joins the components in one network-disabled
container. The actual `sysinfo.lua` returns the synthetic public MAC, `api.lua`
starts Dropbear, and the real SSH service returns a root `id` and canary. The
root shell creates a lab-only user and full-permission profile with the vendor's
JSON schema. After `api.lua` stops Dropbear, the new account logs in through
`login.lua` and reads privileged account information through `users.lua`.

Evidence: `results/evo-5.8.8-http-ssh-root-chain-validation.json` and
`poc/PoC25_XWEB_EVO_SSH_web_persistence.md`. This is post-exploitation
persistence, not an independent account-creation bypass. The new account is a
full-permission regular user, not the special `Administrator` account.

## Remaining device-only gaps

- No physical root SSH login or command execution has been performed.
- Firewall behavior, service startup timing, and exact device MAC/date remain
  runtime properties.
- This is a verified isolated HTTP-to-SSH and web-persistence chain, not a claim
  of access to a production controller or XWEB Pro.

## Next safe validation

On an explicitly owned 5.8.7 or 5.8.8 controller only, use the prepared
`tools/xweb_evo_ssh_chain.py` validator. It reads public system information,
starts SSH, requires a root `uid=0` proof, and stops SSH by default. Do not run
it against third-party Shodan results.
