# EVO isolated ARM/i686 labs

Researcher: Ole-k2.

The launchers and validators use actual recovered vendor code in private
loopback-only QEMU/bubblewrap environments with synthetic users, profiles, and
configuration. No personal remote-device configuration is included or required.

Supply official firmware/rootfs artifacts locally at the ignored paths expected
by `run-evo-arm.sh` and `run-evo-x86.sh`. Review the launchers and each
validator before execution. Validators use fixed canaries, restore original
configuration where applicable, and remove synthetic accounts, sessions,
canaries, and locks.

The shell validators cover factory reset, configuration overwrite, restore
member/server injection, debug backup/restore, download filename, exportpars,
and backup/restore password paths. `evo_archive_tool_probe.py` checks the
negative ZIP/TAR containment result using disposable extraction roots.

For x86 5.8.8, supply `EVO_X86_588_ROOT` and `EVO_X86_588_RUNTIME` to
`run-evo-x86-5.8.8.sh`. Its validators cover service/dependency smoke, self-edit,
locale traversal, image authorization, and native upload parsing.
`forged-update/run-forged-update.sh` separately verifies the unsigned update
command path using a loopback fake repository and a harmless canary, without an
RPM installation, reboot, firmware write, or external network.

E3/Site Supervisor remains at a different boundary: no executable SFUB runtime
has been recovered, so there is no honest E3 QEMU smoke test. Do not infer an
E3 or XWEB Pro exploit from the EVO labs.
