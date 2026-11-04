#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pexpect

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "build/evo-rootfs"
CROSS = REPO / "build/evo-lab/root"
FIXTURE = REPO / "build/evo-dropbear"
RUN = REPO / "build/evo-dropbear-runtime"
RESULT = REPO / "results/evo-5.8.8-dropbear-shell-validation.json"
IMAGE = "embeddedanalyzer/emba:2.0.4b"
PORT = 12222
PASSWORD = "xwebdixO0ANI3"


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def main():
    for directory in (RUN / "tmp", RUN / "var-run", RUN / "root"):
        directory.mkdir(parents=True, exist_ok=True)
    (ROOT / "opt/evo-compat").mkdir(parents=True, exist_ok=True)
    (ROOT / "usr/bin/qemu-arm").touch(exist_ok=True)
    canary = RUN / "tmp/evo-ssh-canary"
    canary.unlink(missing_ok=True)
    name = f"evo-dropbear-canary-{os.getpid()}"
    volumes = [
        (ROOT, "/rootfs", "ro"),
        (CROSS / "lib", "/rootfs/lib", "ro"),
        (Path("/usr/bin/qemu-arm"), "/rootfs/usr/bin/qemu-arm", "ro"),
        (FIXTURE / "passwd", "/rootfs/etc/passwd", "ro"),
        (FIXTURE / "group", "/rootfs/etc/group", "ro"),
        (FIXTURE / "shadow", "/rootfs/etc/shadow", "ro"),
        (FIXTURE / "nsswitch.conf", "/rootfs/etc/nsswitch.conf", "ro"),
        (FIXTURE / "hostkey", "/rootfs/etc/dropbear/hostkey", "ro"),
        (FIXTURE / "root/lib/arm-linux-gnueabi", "/rootfs/opt/evo-compat", "ro"),
        (Path("/dev/urandom"), "/rootfs/dev/urandom", "ro"),
        (Path("/dev/null"), "/rootfs/dev/null", "rw"),
        (RUN / "tmp", "/rootfs/tmp", "rw"),
        (RUN / "var-run", "/rootfs/var/run", "rw"),
        (RUN / "root", "/rootfs/root", "rw"),
    ]
    command = ["run", "--detach", "--name", name, "--network", "none"]
    for source, destination, mode in volumes:
        command.extend(["--volume", f"{source}:{destination}:{mode}"])
    command.extend([
        "--env", "LD_LIBRARY_PATH=/opt/evo-compat:/lib:/usr/lib",
        "--entrypoint", "/usr/sbin/chroot",
        IMAGE, "/rootfs", "/usr/bin/qemu-arm", "-L", "/", "/usr/sbin/dropbear",
        "-F", "-E", "-r", "/etc/dropbear/hostkey",
        "-p", f"127.0.0.1:{PORT}", "-P", "/var/run/dropbear.pid",
    ])
    docker(*command, stdout=subprocess.DEVNULL)
    try:
        time.sleep(1)
        state = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.Running}}", name], text=True
        ).strip()
        if state != "true":
            logs = subprocess.check_output(["docker", "logs", name], text=True)
            raise RuntimeError(f"Dropbear container exited:\n{logs}")
        ssh = pexpect.spawn(
            "docker",
            [
                "exec", "--interactive", "--tty", name,
                "ssh", "-p", str(PORT),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "ConnectTimeout=5",
                "-o", "NumberOfPasswordPrompts=1",
                "root@127.0.0.1",
                "/bin/busybox id; printf EVO_SSH_ROOT_CANARY >/tmp/evo-ssh-canary; /bin/busybox cat /tmp/evo-ssh-canary",
            ],
            encoding="utf-8",
            timeout=15,
        )
        transcript_path = RUN / "client.log"
        with transcript_path.open("w", encoding="utf-8") as transcript:
            ssh.logfile = transcript
            ssh.expect("password:")
            ssh.sendline(PASSWORD)
            ssh.expect(pexpect.EOF)
            output = ssh.before
        ssh.close()
        validated = (
            ssh.exitstatus == 0
            and "uid=0" in output
            and "EVO_SSH_ROOT_CANARY" in output
            and canary.read_text() == "EVO_SSH_ROOT_CANARY"
        )
        result = {
            "scope": "Actual EVO 5.8.8 Dropbear 2022.83 in a network-disabled Docker/QEMU ARM lab with synthetic account data",
            "container_network": "none",
            "server": "127.0.0.1:12222 inside the disposable container",
            "credential": "Documentation-only synthetic daily root credential",
            "password_authentication_validated": True,
            "shell_validated": validated,
            "root_canary_validated": validated,
            "command_output": output.strip(),
            "client_exit_status": ssh.exitstatus,
            "client_signal": ssh.signalstatus,
            "client_log": str(transcript_path.relative_to(REPO)),
            "remaining_limitation": "No physical controller or external network was used; device firewall and service reachability remain unverified",
        }
        RESULT.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0 if validated else 1
    finally:
        logs = subprocess.run(
            ["docker", "logs", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ).stdout
        (RUN / "service.log").write_bytes(logs)
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
