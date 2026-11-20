# Controller lab status

## XWEB EVO service emulation

Recovered XWEB EVO root filesystems support application-level service emulation.
These are not full hardware or refrigeration-controller simulations.

- `./lab/run-evo-arm.sh` runs the EVO 5.8.8 ARM Lighttpd/Lua stack under
  bubblewrap/QEMU with its network namespace disabled.
- `./lab/run-evo-x86.sh` runs the EVO 5.8.7 i686 equivalent.
- `EVO_CONFIG_TEST=1 ./lab/run-evo-arm.sh` runs the ARM configuration-write
  canary. Other `EVO_*_TEST` selectors are defined in the launcher.
- `./lab/run-evo-x86-5.8.8.sh` runs the newly recovered i686 5.8.8 stack.
  Supply `EVO_X86_588_ROOT` and a disposable `EVO_X86_588_RUNTIME`, then select
  `EVO_TEST_SCRIPT=evo-x86-5.8.8-smoke-test.sh`, `...-deps-test.sh`,
  `...-self-edit-test.sh`, `...-locale-traversal-test.sh`,
  `...-images-test.sh`, or `...-upload-parser-test.sh`.
- `EVO_EMAIL_TEST=1 ./lab/run-evo-x86.sh` validates the real `msmtp`
  configuration-directive injection. The launcher supplies the local `msmtp`
  compatibility binary and writable log directory.
- `lab/forged-update/` contains the loopback-only unsigned-update validator.
  It creates a harmless canary only; no RPM, reboot, firmware write, or external
  repository is used. See PoC30 for its launcher and cleanup contract.
- `python3 lab/evo-arm-dropbear-canary.py` starts the recovered Dropbear 2022.83
  in a disposable network-disabled Docker container, authenticates with the
  documentation-only synthetic daily credential, runs `id`, writes a fixed root
  canary, and removes the container. It requires the existing EMBA image,
  Docker access, `pexpect`, and the derived files under `build/`.
- `python3 lab/evo-arm-ssh-chain-canary.py` runs the complete public-sysinfo →
  API SSH start → root SSH canary → lab web-account creation → API SSH stop →
  privileged web-login sequence. Account files are created only in scratch
  storage and the container is removed.
- `EVO_MBIRD_TEST=1 python3 lab/evo-arm-ssh-chain-canary.py` verifies the
  MessageBird settings-edit command-injection path with an Administrator-terminal
  negative control and a root `id` canary.

Dropbear evidence is written to
`results/evo-5.8.8-dropbear-shell-validation.json`; service and client logs are
under `build/evo-dropbear-runtime/`.

## E3 / Site Supervisor limitation

The downloaded SFUB containers still do not expose executable applications, a
kernel, a root filesystem, or a loadable disk image through standard offline
extraction. There is no honest full-system QEMU target for those packages.
EVO service emulation does not change that boundary.

To enable E3 runtime work, obtain a decrypted firmware/rootfs with its runtime
libraries, an authorized controller for non-destructive tests, or vendor
update/emulation tooling that lawfully exposes the package contents.

Runtime tests must remain isolated, use non-destructive markers, avoid
persistent changes, and distinguish application responses from actual
operating-system or refrigeration-control impact. Do not test production or
internet-facing controllers.
