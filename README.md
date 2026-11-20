# Copeland / Dixell XWEB Security Research

**Independent firmware analysis, public decoders, and authorization-gated PoCs for defending your own equipment.**

Researcher: **Ole-k2**

> **The short version:** on the tested XWEB EVO 5.8.8 firmware, an attacker with
> any valid web account—even one with almost no permissions—can run commands as
> root through the account self-edit function. Separate tests showed that the
> updater accepts commands from unsigned update metadata. Other PoCs cover file
> writes, information disclosure, command injection, predictable credentials,
> and web attacks across older EVO/XWEB releases.

## Why this matters

These controllers manage refrigeration and industrial equipment. Root access can
mean more than changing a web page: it can expose configuration and credentials,
interrupt monitoring, alter controller behavior, and provide a foothold in the
attached operational network.

Copeland has stated that **XWEB EVO reached End of Support in March 2026** and
will receive no further security fixes. The practical advice for operators is:

1. Do not expose EVO web or SSH services to the Internet or untrusted networks.
2. Restrict them to a dedicated management network or VPN and review every account.
3. Replace default/reused credentials and remove accounts that are not required.
4. Plan migration to a supported product using Copeland's published upgrade resources.
5. Monitor self-edit, upload, locale, restore, update, SSH, and login activity.

**Scope matters:** this repository does not claim a current XWEB PRO or E3/Site
Supervisor exploit. PRO packages use a different signed/encrypted design, and
the EVO findings must not automatically be attributed to those products.

## What is new in the x86 EVO 5.8.8 assessment

A newly listed official i686 package was decoded and run in an isolated lab. All
reported dynamic results used genuine vendor code, synthetic accounts, loopback
services, and harmless canaries—not a researcher's remote device.

| PoC | Result | What an attacker needs |
|---|---|---|
| [28](poc/PoC28_XWEB_EVO_self_edit_root_command_injection.md) | Root command execution through self-edit `username` | Any valid web account |
| [29](poc/PoC29_XWEB_EVO_locale_traversal.md) | Write/delete `.json` files outside the locale directory | `languages-edit` role |
| [30](poc/PoC30_XWEB_EVO_unsigned_update_command_execution.md) | Command execution through unsigned update metadata | Authenticated update path or attacker-controlled package source |
| [31](poc/PoC31_XWEB_EVO_image_upload_authorization.md) | Stored SVG/image upload and deletion | Any valid web account |
| [32](poc/PoC32_XWEB_EVO_doevo_xss_specialuser.md) | Script-breakout XSS; forgeable feature token | XSS needs a victim browser; token alone is not a login |
| [33](poc/PoC33_XWEB_EVO_native_upload_parser.md) | Plaintext arbitrary write, native crashes, limited pre-auth staging | Write/crash paths need a session; one staging path does not |
| [34](poc/PoC34_XWEB_EVO_shared_credentials_tls_key.md) | Shared `dixell:dixell` credential and firmware-wide TLS private key | Static verification in both official trees; no login or TLS interception tested |

The complete technical report is
[`analysis/XWEB-EVO-5.8.8-X86.md`](analysis/XWEB-EVO-5.8.8-X86.md). All ten
previous x86 regression validators also passed on 5.8.8.

## Run an authorized check on your own device

The unified runner supports a bare IP, hostname, `host:port`, or HTTP(S) URL.
Plain HTTP is the default when no scheme is supplied. Every device-contacting
mode requires `--authorized` and uses a harmless, uniquely named canary with
cleanup. Output is sanitized and does not include the target, credentials,
session tokens, MAC addresses, or raw device responses.

```bash
git clone https://github.com/Kjartansson/Ole-K2-Copeland-Firmware-Disclosure.git
cd Ole-K2-Copeland-Firmware-Disclosure
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tools/xweb_evo_remote.py list
```

Interactive selection:

```bash
.venv/bin/python tools/xweb_evo_remote.py --authorized
```

Direct examples use TEST-NET placeholders, not researcher devices:

```bash
# Read the public release fingerprint only
.venv/bin/python tools/xweb_evo_remote.py info 192.0.2.10 --authorized

# Any-account self-edit command-injection check; prompts for the password
.venv/bin/python tools/xweb_evo_remote.py self-edit 192.0.2.10 \
  --authorized --username operator

# Locale traversal check with an account that has languages-edit
.venv/bin/python tools/xweb_evo_remote.py locale 192.0.2.10 \
  --authorized --username language-editor

# Stored-image authorization check
.venv/bin/python tools/xweb_evo_remote.py images https://192.0.2.10 \
  --authorized --username operator --insecure

# Unauthenticated reflection and feature-token checks
.venv/bin/python tools/xweb_evo_remote.py xss 192.0.2.10 --authorized
.venv/bin/python tools/xweb_evo_remote.py specialuser 192.0.2.10 --authorized
```

Use `--insecure` only for a device with a self-signed certificate that you
explicitly trust. Credentials can also be supplied through
`XWEB_EVO_USERNAME` and `XWEB_EVO_PASSWORD`; interactive password entry avoids
putting a password in shell history. `--json results/report.json` writes a
sanitized result. The `results/` directory is ignored by Git.

Exit codes are `0` confirmed, `1` not confirmed, `2` usage/authorization error,
`3` unreachable, `4` authentication failed, and `5` cleanup incomplete. A
permission-denied result can mean the account is too restricted to test that
path; it is not proof that the device is patched.

### Additional targeted validators

The repository retains separate authorized validators for the earlier
Administrator command-injection and daily-credential SSH chains:

```bash
.venv/bin/python tools/xweb_evo_rce.py https://192.0.2.10 --authorized
.venv/bin/python tools/xweb_evo_ssh_chain.py https://192.0.2.10 --authorized
```

The first performs an Administrator canary and cleanup. The second starts SSH,
checks the derived root credential, and stops SSH unless `--keep-ssh` is given.
Review the corresponding PoC12/PoC13 documents before using them.

**Lab-only cases:** forged firmware updates, factory resets, persistence,
firmware writes, and real reboot paths are deliberately not offered as one-click
remote tests. Use the isolated lab instructions instead.

## Public decoders and educational material

The decoders run locally and do not contact a controller. They are useful for
learning container formats, XOR obfuscation, CPIO/RPM recovery, and how to tell
obfuscation from actual cryptography.

```bash
# Recover EVO/FCEVO RPMs and XML descriptors from an official x86 update
python3 tools/xweb_evo_xor_extract.py OFFICIAL_EVO.zip recovered/x86

# Decode an EVO .epkg installer and record its hash/container metadata
python3 tools/xweb_epkg_decrypt.py INPUT.epkg OUTPUT.decoded \
  --json results/decode-result.json

# Recover older XWEB2009 RPM/cpio content
python3 tools/xweb2009_xor_extract.py OFFICIAL_XWEB2009.zip recovered/legacy
```

See [`DECODERS.md`](DECODERS.md) for the algorithms, XWEB500 UF extraction,
validation requirements, and the E3/PRO research boundary. Experimental
OpenSSL/SFUB probes are included for reproducibility and education; **no working
PRO or E3/Site Supervisor decryptor is claimed**. Official firmware archives and
recovered proprietary images are not redistributed.

## Reproduce in the isolated lab

The lab uses operator-supplied official firmware, QEMU, and bubblewrap. Network
namespaces are loopback-only; accounts, profiles, sessions, and canaries are
synthetic. Example for the new x86 tests:

```bash
export EVO_X86_588_ROOT=/path/to/derived-5.8.8-rootfs
export EVO_X86_588_RUNTIME=/path/to/disposable-runtime
EVO_TEST_SCRIPT=evo-x86-5.8.8-self-edit-test.sh ./lab/run-evo-x86-5.8.8.sh
EVO_TEST_SCRIPT=evo-x86-5.8.8-locale-traversal-test.sh ./lab/run-evo-x86-5.8.8.sh
EVO_TEST_SCRIPT=evo-x86-5.8.8-images-test.sh ./lab/run-evo-x86-5.8.8.sh
EVO_TEST_SCRIPT=evo-x86-5.8.8-upload-parser-test.sh ./lab/run-evo-x86-5.8.8.sh
lab/forged-update/run-forged-update.sh
```

The earlier x86 validators are available through `lab/run-evo-x86.sh`, for
example `EVO_EMAIL_TEST=1` or `EVO_RESTORE_TEST=1`. The restore validator accepts
`EVO_EXPECT_RELEASE` and defaults to 5.8.7. Review each script before execution.

## Full PoC coverage

See the [complete PoC index](poc/README.md).

- **PoC2–PoC11:** legacy XWEB2009/XWEB500/EVO package recovery, authentication
  weaknesses, file access, SQL and command injection, and hardcoded credentials.
- **PoC12–PoC27:** daily-credential SSH paths, Administrator and low-role command
  injection, configuration writes, information disclosure, restore/backup paths,
  factory reset, persistence, MessageBird, and email configuration injection.
- **PoC28–PoC34:** new x86 EVO 5.8.8 self-edit, locale, update, image, `doevo.cgi`,
  native upload-parser, and shared credential/TLS findings.

Evidence is labeled honestly: static recovery, local compatibility models,
actual vendor code in an isolated runtime, and authorized physical-device checks
are different levels of proof. The disproven SFUB ECB-malleability claim is
excluded. PoC1 is not presented as a working exploit.

## Privacy and responsible use

The public tree contains no personal remote-device information, private
configuration, live credentials, session tokens, customer data, or raw device
captures. Example addresses are loopback or TEST-NET values; example credentials
are synthetic lab fixtures. Raw results and local firmware/build directories are
ignored by Git.

Use this material only on equipment you own or are explicitly authorized to
test. Prefer an isolated lab or a disposable device image. Do not run update,
factory-reset, persistence, or destructive filesystem paths on production
systems. Sanitize any output you share.

Earlier public release was approved on 2026-11-03. The newer findings retain the
same EVO End-of-Support boundary; no additional vendor response is implied.

## Why this is published for education

Copeland PSIRT replied to the initial report that all XWEB EVO models reached
End of Support in March 2026. Its response points to the product bulletin's
warnings about direct Internet exposure, available upgrade resources, and the
absence of further security updates or vulnerability fixes. It also thanks the
researcher for responsibly disclosing the findings and helping improve
cybersecurity awareness.

Publishing the decoders and safe PoCs therefore serves an educational and
defensive purpose: operators can understand the weaknesses, test their own
equipment, and make informed isolation and migration decisions. It is not an
endorsement of unauthorized exploitation or a claim that Copeland reviewed or
approved each later technical result. See
[`submission/DISCLOSURE-STATUS.md`](submission/DISCLOSURE-STATUS.md).

## Disclosure and attribution

Copeland's response stated that EVO is End of Support and recommended upgrade
resources and avoiding direct Internet exposure.

Independent research, not affiliated with or endorsed by Copeland or Dixell.
Publicly known CVEs and third-party research are not presented as Ole-k2
discoveries. Public firmware was obtained from official public downloads
without bypassing authentication, licensing, or access controls.
