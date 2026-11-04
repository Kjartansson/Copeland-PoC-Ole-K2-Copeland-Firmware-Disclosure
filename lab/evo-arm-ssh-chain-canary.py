#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlencode

import pexpect

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "build/evo-rootfs"
CROSS = REPO / "build/evo-lab/root"
LUA = REPO / "build/evo-lua-arm"
FIXTURE = REPO / "build/evo-dropbear"
RUNTIME = REPO / "build/evo-runtime"
RUN = REPO / "build/evo-chain-runtime"
RESULT = REPO / "results/evo-5.8.8-http-ssh-root-chain-validation.json"
IMAGE = "embeddedanalyzer/emba:2.0.4b"
DAILY = "O0ANI3"
ROOT_PASSWORD = "xwebdixO0ANI3"
LAB_PASSWORD = "LabOnly-2026!"


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def request(name, path, **fields):
    args = ["exec", name, "curl", "-fsS"]
    if fields:
        args.extend(["-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded", "--data", urlencode(fields)])
    args.append(f"http://127.0.0.1:18080{path}")
    output = subprocess.check_output(["docker", *args], text=True)
    return json.loads(output)


def ssh(name, command):
    child = pexpect.spawn(
        "docker",
        [
            "exec", "--interactive", "--tty", name,
            "ssh", "-p", "22",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "ConnectTimeout=5",
            "-o", "NumberOfPasswordPrompts=1",
            "root@127.0.0.1", command,
        ],
        encoding="utf-8",
        timeout=20,
    )
    transcript = RUN / "ssh-client.log"
    with transcript.open("a", encoding="utf-8") as log:
        child.logfile = log
        child.expect("password:")
        child.sendline(ROOT_PASSWORD)
        child.expect(pexpect.EOF)
        output = child.before
    child.close()
    if child.exitstatus != 0:
        raise RuntimeError(f"SSH command failed with status {child.exitstatus}: {output}")
    return output


def password_hash(password, salt, iterations=5000):
    value = password
    for _ in range(iterations):
        value = hashlib.sha256((value + salt).encode()).hexdigest()
    return value


def main():
    if RUN.exists():
        docker(
            "run", "--rm", "--network", "none", "--volume", f"{RUN}:/scratch:rw",
            "--entrypoint", "/bin/sh", IMAGE, "-c", "rm -rf /scratch/*",
            stdout=subprocess.DEVNULL,
        )
        shutil.rmtree(RUN)
    for directory in ("tmp", "shm", "opt-tmp", "opt-log", "var-log/lighttpd", "var-run", "root", "dropbear"):
        (RUN / directory).mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "opt/setup", RUN / "setup")
    shutil.copy(FIXTURE / "hostkey", RUN / "dropbear/dropbear_rsa_host_key")
    (RUN / "dropbear/dropbear.conf").write_text(
        'PORTSETUP="-p 127.0.0.1:22 -r /etc/dropbear/dropbear_rsa_host_key"\n'
    )
    (RUN / "xwebconfig.json").write_text(json.dumps({
        "model_type": "XWEB300D",
        "CPF": "LOCALTEST",
        "performance": 0,
        "scheduler": 0,
        "cro_engines": 0,
        "dewpoint": 0,
        "automations_compressors_guard": 0,
        "automations_eco2": 0,
        "supervision": 0,
        "documents": 0,
        "datapush": 0,
        "custom_arneg": 0,
        "layout": 0,
        "custom_lidl": 0,
        "ldap": 0,
    }))
    (RUN / "ssh-client.log").touch()
    (ROOT / "usr/bin/qemu-arm").touch(exist_ok=True)
    (ROOT / "usr/bin/start-stop-daemon").touch(exist_ok=True)
    for directory in (
        ROOT / "opt/evo-compat/sysroot/lib",
        ROOT / "opt/evo-compat/lua",
        ROOT / "opt/evo-compat/dropbear-lib",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    lua_modules = {
        "liblua5.1-cjson.so.0.0.0": "cjson.so",
        "liblua5.1-filesystem.so.0.0.0": "lfs.so",
        "liblua5.1-sql-sqlite3.so.2.0.0": "lsqlite3.so",
    }
    for source in lua_modules.values():
        (ROOT / "opt/evo-compat/lua" / source).touch(exist_ok=True)
    (ROOT / "opt/evo-compat/sysroot/lib/ld-linux.so.3").touch(exist_ok=True)

    name = f"evo-http-ssh-chain-{os.getpid()}"
    volumes = [
        (ROOT, "/rootfs", "ro"),
        (CROSS / "lib", "/rootfs/lib", "ro"),
        (Path("/usr/bin/qemu-arm"), "/rootfs/usr/bin/qemu-arm", "ro"),
        (ROOT / "bin/busybox", "/rootfs/usr/bin/start-stop-daemon", "ro"),
        (CROSS / "lib/ld-linux.so.3", "/rootfs/opt/evo-compat/sysroot/lib/ld-linux.so.3", "ro"),
        (LUA / "compat", "/rootfs/opt/evo-compat/compat", "ro"),
        (LUA / "root/lib/arm-linux-gnueabi", "/rootfs/opt/evo-compat/lib", "ro"),
        (LUA / "root/usr/lib/arm-linux-gnueabi", "/rootfs/opt/evo-compat/usr-lib", "ro"),
        (LUA / "root/usr/bin/lua5.1", "/rootfs/usr/bin/lua", "ro"),
    ]
    for source, destination in lua_modules.items():
        volumes.append((LUA / "root/usr/lib/arm-linux-gnueabi" / source, f"/rootfs/opt/evo-compat/lua/{destination}", "ro"))
    volumes.extend([
        (FIXTURE / "passwd", "/rootfs/etc/passwd", "ro"),
        (FIXTURE / "group", "/rootfs/etc/group", "ro"),
        (FIXTURE / "shadow", "/rootfs/etc/shadow", "ro"),
        (FIXTURE / "nsswitch.conf", "/rootfs/etc/nsswitch.conf", "ro"),
        (FIXTURE / "root/lib/arm-linux-gnueabi", "/rootfs/opt/evo-compat/dropbear-lib", "ro"),
        (RUNTIME / "lighttpd-custom.conf", "/rootfs/etc/lighttpd/lighttpd-custom.conf", "ro"),
        (RUN / "xwebconfig.json", "/rootfs/etc/xwebconfig.json", "ro"),
        (RUNTIME / "xwpasswd", "/rootfs/opt/xweb/bin/tools/xwpasswd", "ro"),
        (RUNTIME / "ip", "/rootfs/usr/bin/ip", "ro"),
        (RUNTIME / "curl", "/rootfs/usr/bin/curl", "ro"),
        (ROOT / "bin/busybox", "/rootfs/usr/bin/find", "ro"),
        (ROOT / "bin/busybox", "/rootfs/bin/sleep", "ro"),
        (Path("/dev/urandom"), "/rootfs/dev/urandom", "ro"),
        (Path("/dev/null"), "/rootfs/dev/null", "rw"),
        (RUN / "dropbear", "/rootfs/etc/dropbear", "rw"),
        (RUN / "setup", "/rootfs/opt/setup", "rw"),
        (RUN / "tmp", "/rootfs/tmp", "rw"),
        (RUN / "shm", "/rootfs/dev/shm", "rw"),
        (RUN / "opt-tmp", "/rootfs/opt/tmp", "rw"),
        (RUN / "opt-log", "/rootfs/opt/log", "rw"),
        (RUN / "var-log", "/rootfs/var/log", "rw"),
        (RUN / "var-run", "/rootfs/var/run", "rw"),
        (RUN / "root", "/rootfs/root", "rw"),
    ])
    command = ["run", "--detach", "--name", name, "--network", "none"]
    for source, destination, mode in volumes:
        command.extend(["--volume", f"{source}:{destination}:{mode}"])
    command.extend([
        "--env", "LD_LIBRARY_PATH=/opt/evo-compat/dropbear-lib:/opt/evo-compat/compat:/opt/evo-compat/lib:/opt/evo-compat/usr-lib:/lib:/usr/lib",
        "--env", "LUA_CPATH=/opt/evo-compat/lua/?.so;;",
        "--env", "QEMU_LD_PREFIX=/opt/evo-compat/sysroot",
        "--env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/xweb/bin/tools",
        "--entrypoint", "/bin/sleep", IMAGE, "infinity",
    ])
    docker(*command, stdout=subprocess.DEVNULL)
    lighttpd = None
    try:
        lighttpd_log = (RUN / "lighttpd.log").open("wb")
        lighttpd = subprocess.Popen(
            [
                "docker", "exec", name, "chroot", "/rootfs", "/usr/bin/qemu-arm",
                "-L", "/opt/evo-compat/sysroot", "/usr/sbin/lighttpd",
                "-f", "/etc/lighttpd/lighttpd.conf", "-D",
            ],
            stdout=lighttpd_log,
            stderr=subprocess.STDOUT,
        )
        sysinfo = None
        for _ in range(20):
            try:
                sysinfo = request(name, "/cgi-bin/sysinfo.lua")
                break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                time.sleep(0.25)
        if not sysinfo:
            raise RuntimeError("Lighttpd did not return sysinfo")
        if sysinfo.get("info", {}).get("id") != "001122334455":
            raise RuntimeError(f"Unexpected public sysinfo: {sysinfo}")

        start = request(name, "/cgi-bin/api.lua", action="ssh", password=DAILY, target="start")
        if start.get("SSH") != "start":
            raise RuntimeError(f"SSH start failed: {start}")
        time.sleep(1)

        schema = json.loads((ROOT / "opt/xweb/permissions.json").read_text())
        permissions = {context: {permission: 1 for permission in values} for context, values in schema.items()}
        profile_config = {"id": 99, "label": "Lab full-permission profile"}
        salt = "lab-only-salt"
        user_config = {
            "id": 2,
            "username": "labadmin",
            "password_mode": "sha256",
            "password_salt": salt,
            "password_iterations": 5000,
            "password_hash": password_hash(LAB_PASSWORD, salt),
            "password_expiration": -1,
            "enabled": True,
            "expiration_date": 0,
            "profile": 99,
            "label": "Lab-only account",
            "language": "en-GB",
            "default_desktop": "dashboard",
            "dashboard_default_view": "alarms",
        }
        writes = [
            ("/opt/setup/profiles/99/config.json", profile_config),
            ("/opt/setup/profiles/99/permissions.json", permissions),
            ("/opt/setup/profiles/99/layout.json", {}),
            ("/opt/setup/users/2/config.json", user_config),
        ]
        shell_command = (
            "/bin/busybox id; printf EVO_SSH_ROOT_CANARY >/tmp/evo-ssh-canary; "
            "/bin/busybox chmod 644 /tmp/evo-ssh-canary; "
            "/bin/busybox mkdir -p /opt/setup/profiles/99 /opt/setup/users/2; "
        )
        for path, value in writes:
            encoded = json.dumps(value, separators=(",", ":"))
            shell_command += f"printf '%s' '{encoded}' >{path}; "
        shell_command += "/bin/busybox touch /opt/setup/users/2/labadmin; printf LAB_USER_CREATED"
        root_output = ssh(name, shell_command)
        if "uid=0" not in root_output or "LAB_USER_CREATED" not in root_output:
            raise RuntimeError(f"Root canary/account creation failed: {root_output}")
        if (RUN / "tmp/evo-ssh-canary").read_text() != "EVO_SSH_ROOT_CANARY":
            raise RuntimeError("SSH canary missing")

        stop = request(name, "/cgi-bin/api.lua", action="ssh", password=DAILY, target="stop")
        login = request(
            name,
            "/cgi-bin/login.lua",
            action="login",
            auth_mode="standard",
            username="labadmin",
            password=LAB_PASSWORD,
            initparam="-1",
        )
        if login.get("status") != "ok":
            raise RuntimeError(f"Lab user login failed after SSH was stopped: {login}")
        session = login["user"]["sses"]
        users = request(name, "/cgi-bin/users.lua", action="get", SSES=session)
        if "2" not in users.get("users", {}):
            raise RuntimeError(f"Lab user cannot read its privileged user information: {users}")
        result = {
            "scope": "Actual EVO 5.8.8 Lighttpd/Lua and Dropbear in one network-disabled Docker/QEMU ARM lab",
            "public_sysinfo_id": sysinfo["info"]["id"],
            "api_ssh_start": start,
            "root_output": root_output.strip(),
            "root_canary_validated": True,
            "lab_user_created_over_ssh": True,
            "api_ssh_stop": stop,
            "lab_user_login_after_ssh_stop": login["status"],
            "lab_user_id": login["user"]["id"],
            "lab_profile_id": login["user"]["profile"],
            "privileged_user_info_validated": True,
            "validated": True,
            "limitations": [
                "No physical controller or external network was used",
                "MAC, credentials, account, and profile are synthetic lab-only values",
                "The lab user is a full-permission regular account, not the special Administrator account",
                "Physical device firewall and service behavior remain unverified"
            ],
        }
        RESULT.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0
    finally:
        if lighttpd is not None:
            lighttpd.terminate()
            try:
                lighttpd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                lighttpd.kill()
                lighttpd.wait(timeout=5)
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
