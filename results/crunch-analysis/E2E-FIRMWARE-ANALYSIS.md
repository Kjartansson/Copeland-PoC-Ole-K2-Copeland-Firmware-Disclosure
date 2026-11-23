# Recovered E2E 4.11F03 main firmware — static analysis

Date: 2026-11-23. Lane: Copeland code recovery, follow-up to
`results/crunch-runtime/RECOVERY.md` (same day). All work static/offline on
the locally recovered image; no device contacted.

Input: `results/crunch-runtime/e2_fw-vxWorks.decoded.bin`, SHA-256
`80204568f1ddfe8202f5781657c80c50766f1c2b1070c95c244a1392bf1c7c9f`
(re-verified before use). Working copy:
`build/crunch-analysis/e2_fw-vxWorks-4.11F03.elf` (same hash).
Analysis note: the last 20 file bytes are decoder padding (RECOVERY.md); they
corrupt only the trailing shstrtab section header (section 6), so `readelf`
warns and `objdump` refuses the ELF. All LOAD segments are intact; analysis
used raw segment extracts `build/crunch-analysis/e2_fw.text.bin`
(.text @0x608000) and `e2_fw.data.bin` (.data @0xf25000) with
`objdump -D -b binary -m i386 --adjust-vma=...`.

## Image identity (E2 facts)

- ELF32 EXEC i386, entry 0x608000, VxWorks 6.8 boot (GPC PENTIUM2), Wind River
  copyright 1984-2004; source tree `C:/code/E2ESoftware/Software/code/Source/...`.
- This is the complete E2E main application: HVAC/refrigeration controller
  business logic (AnalogIn, suction groups, schedules), UI (PegScreen),
  BACnet-style access-control objects, plus the network stack.
- The image ships with a standalone VxWorks symbol table. 29,365 unique
  symbols (name→address) were extracted to
  `build/crunch-analysis/e2_fw-vxworks-symbols.txt`; demangled inventory in
  `e2_fw-symbols-demangled.txt`. C++ class layout matches the updater ELF
  (`CpcPackage`, `Crunch`, `CpcEncryption` all present in both).

## Services (E2 facts)

- **HTTP**: GoAhead-Webs server ("GoAhead-Webs", "webs: Listening for HTTP
  requests at address %s"). `WebServerTask` is started from `StarterTask` via
  `CpcIPConnMgr::initializeWebServer` (call at 0x6783c6). `SetWebServerPort`
  exists; "SYSUPDATE Web Server Access Port" is a persisted config item.
  Authentication: HTTP Basic (`WWW-Authenticate: Basic realm="%s"`).
  ASP handlers include `aspClientLogin`, `aspGetAccessLevel`.
- **JSON-RPC**: endpoint `/JSON-RPC` with methods `E2.ClientLogin`,
  `E2.ClientLogout`, `E2.GetLoginInfo`, `E2.Get/SetConfigValues`,
  `E2.Override`, `E2.MultiOverride`, `E2.SetValue`, alarm/log getters, etc.
  (~37 methods; full list via `grep -ao 'E2\.[A-Za-z]*'`).
- **UltraSite remote client**: `ConnAccepter` listener, `CpcIPConnection`,
  `UltraSiteConnection`. `CpcValidateRemoteClient` (0x98b4d8) checks a
  `CPCR` magic and Blowfish-decrypts the payload; "Firewall Remote Client
  Port"/"Remote Client Port" are persisted config items.
- **E2 peer-to-peer**: `CpcE2Peer::authenticateConnection`,
  `sendMessage`/`getCommandFromConnection` use `CpcEncryption::EncryptData`/
  `DecryptData` (Blowfish-encrypted peer protocol).
- **SNMP**: `CpcSnmpListener`, `CpcSnmpTransaction*`, enterprise OID prefix
  `1.3.6.1.4.1.9615` (Emerson); SNMP device scan logic present.
- **FTP**: Wind River/Interpeak `ipftps` server library is linked (banner
  "220 Wind River FTP server", `ftpLogin`, `ipftps_start` 0xb3f410) but
  `ipftps_start` has **no direct call site**; the only reference is a pointer
  in .data (file 0x9cdc70, likely a component-config table). Whether the FTP
  daemon actually runs on a device is unresolved from static analysis.
- **Telnet**: no telnet daemon found (only `ipcom_telnet`/TELNETD library
  strings). `shellLoginInstall` (0xbc5160) has no direct call site either.
- No SSH.

## Account / credential handling (E2 facts)

- Login funnel: `cpcLoginSession` (0xa49fa0) → `AccessServices::GetUserData`
  (0x89ad10) validates username/password and returns an access level; on
  success a `CpcSession` (cookie handle, expiration, per-session username)
  is added to `CpcSessionList`. Call-site analysis: `cpcLoginSession` has
  exactly two callers, `JSONRPC_ClientLogin` and `aspClientLogin` — the
  web UI and `/JSON-RPC` login paths, so the accounts below are reachable
  through the device web server (code-path fact; no device was contacted).
  (Ghidra decompilation:
  `build/crunch-analysis/ghidra-export/decomp_cpcLoginSession.c`,
  `decomp__ZN14AccessServices11GetUserDataEPcS0_RhRmPt.c`.)
- **Hardcoded service accounts in `GetUserData`** (decompiled verbatim):
  - Username `ONEDAY` (string at 0xcce2d8): authenticates at access level 5
    with permission mask 0x708; its password buffer (BSS 0xcce28c) is zero
    in the image — the comparison is `stricmp(password, "")`, i.e. an empty
    password unless something initializes the BSS slot at runtime
    (no writer found in static analysis so far).
  - Username `CPC` (0xcce2df): password computed by
    `AccessServices::CalculateSalPassword(month, day, 1, buf)` → access
    level 5, mask 0x708.
  - Username `CPC3` (0xcce2e3): `CalculateSalPassword(month, day, 0, buf)`
    → access level 0.
  - Otherwise: linear scan of 25 configured user records (stride 0x1e;
    username at +0xd4, **cleartext** password at +0xe4), compared with
    `stricmp` — case-insensitive cleartext comparison.
- `CalculateSalPassword` (0x899a10, disassembly-verified) computes a
  **date-derived 3-digit service PIN**:
  `n = (month + 0x15) * (day + day mod 7) mod 1000`, formatted as
  `CPC%03d` (type 1) or `USR%03d` (type 0; format strings at 0xd2545f /
  0xd25457). On day-of-month 1 with license feature 0x4e25 granted it falls
  back to `sprintf(buf, "%c", 9)`. So the CPC/CPC3 service passwords are
  predictable from the controller date — a vendor service-login mechanism
  baked into the firmware.
- Local screen passwords in config are numeric 16-bit fields
  (`stConfigurationStatus.wPassword = %d`,
  `blEnableNormalPassword`/`wNormalPassword`/`wAdvancedPassword`) —
  a 0..65535 space.
- MD5 is present (OpenSSL 0.9.8e + ipmcrypto) but its only callers are the
  IP stack (`ipcom_random_*`, `iptcp_pkt_drain`, `ipmcrypto_md5_calculate`) —
  it is not used for password hashing at application level.

## Updater / package logic (E2 facts)

- Classes `CpcPackage`/`CpcPackageElement` and `E2FirmwareUpdate` /
  `E2FWUPCollection` implement the CpcPackage update flow:
  `Transfer` (writes `/ata00:2/e2_fw.pkg`), `validatePackage` /
  `validatePackageContents`, `Apply` (thin stub → `Rename` → `Reboot`).
- `validatePackage` (0x999e90) performs only `CpcRevision` comparisons,
  patch-from-version checks, schema/element lookups
  (`getPatchFromVersion`, `containsPatch`, `getElementByName`).
  Direct-call analysis of the whole update path (`CpcPackage::unpack`,
  `E2FU::Transfer`, `validatePackage(Contents)`,
  `handleE2FWValidateTransfer`, `handleE2FWTransfer`,
  `E2FWUPCollection::validateTransferPackageTask`) finds **zero calls to any
  crypto function** (no Blowfish, no MD5, no hash/signature verify).
  Combined with the fully decodable unsigned 4.11F03 container
  (RECOVERY.md, STREAMS.md), the E2E update package has no authenticity
  protection: Crunch compression only.
- The `Crunch` codec class (`Crunch::DeCompressData`, magic-mode semantics as
  recovered) is compiled into the main firmware too — same code as analyzed
  in the updater ELF.

## Crypto / key handling (E2 facts)

- `CpcEncryption`: Blowfish ECB with the **same signed-byte (`movsx`) key
  schedule quirk** previously documented in the updater ELF
  (`analysis/E2E-UPDATER.md`): `Blowfish_Init` at 0x9758e0 loads key bytes
  with `movsx` (verified at 0x975946).
- `concatenateEncryptionKey` (0x975ec0) builds the key as
  `sprintf(buf, "%s%s", input, "kb?A68D+tl?2@KL_")` — the same 16-byte salt
  constant as the updater (here at file offset 0x722f7c / vaddr 0xd29f7c).
- Uses: license feature activation (`CpcLicenseManager::activateFeature`
  decrypts feature keys; `genkey` encrypts), UltraSite remote-client
  protocol, E2 peer protocol, and protected config
  (`SysConfigInitialize` calls `decryptBuffer`; `testEncryption` self-test).
- No AES, DES/3DES, RSA, SHA-1, or HMAC anywhere in the symbol table.

## SFUB presence (E2 fact: absent)

- No `SFUB`/`SFUB_update` string or symbol in the image (also verified in
  RECOVERY.md). No SFUB parser, no 8-byte-ECB package handler. The only
  package format this firmware understands is CpcPackage (Crunch elements).

## E3/Site Supervisor relevance

E2 facts above. Hypotheses explicitly marked:

- The E2E 4.11F03 image proves vendor-wide use of (a) Crunch magic-header
  containers, (b) signed-byte Blowfish with a hardcoded 16-byte salt, (c)
  salt-concatenation key derivation — all in the E2/E2E generation.
  Whether any of these are reused in E3/SS SFUB is **unproven**; prior
  bounded probes of updater-derived Blowfish candidates against SFUB produced
  zero hits (`results/related-binary-probe.json` etc.), and this lane ran no
  new ciphertext/password campaign.
- The recovered image supplies 29,365 new related-code strings/symbols and a
  complete related-code sample for any future *authorized* comparison, but it
  contains no E3/SS artifact, no SFUB key material, and no E3/SS access path.
- Genuine-access angle (E2 fact, not an E3 path): the E2E update container
  is unsigned and the firmware's update validation is schema-only; and the
  E2E web/JSON-RPC login accepts hardcoded service accounts (CPC/CPC3 with a
  date-derived 3-digit PIN, ONEDAY with an empty static password buffer).
  Both are properties of the E2E product only. Whether E3/SS inherited any
  of this code is unknown — no E3/SS updater or rootfs has been recovered,
  and no claim is made.

## Ghidra

The recovered ELF's trailing shstrtab section header (section 6) is damaged by
the 20-byte decoder padding (RECOVERY.md): its fields read `0x94949494`, and
Ghidra 12.2's ELF loader spun indefinitely on it (JVM stuck pre-import,
6 MB RSS, no progress for 20 min). A section-sanitized working copy
`build/crunch-analysis/e2_fw-vxWorks-4.11F03-nosec.elf` (identical bytes
except `e_shoff`/`e_shnum`/`e_shstrndx` zeroed; all LOAD segments untouched;
original `results/crunch-runtime/e2_fw-vxWorks.decoded.bin` preserved) imports
cleanly. Headless command:

    analyzeHeadless $PWD/ghidra CopelandE3 \
        -import $PWD/build/crunch-analysis/e2_fw-vxWorks-4.11F03-nosec.elf \
        -overwrite -analysisTimeoutPerFile 3600

Post-scripts (Java; Ghidra 12.2 headless has no Jython/PyGhidra here):
`build/crunch-analysis/ghidra_scripts/ApplyE2Symbols.java` and
`ExportE2Analysis.java`, run with `-process e2_fw-vxWorks-4.11F03-nosec.elf
-noanalysis -postScript ...`.

Outcome:

- Auto-analysis succeeded in 1,519 s; program saved as
  `CopelandE3:/e2_fw-vxWorks-4.11F03-nosec.elf` in `ghidra/CopelandE3.gpr`.
- Ghidra found **22,813 functions**; all **29,365 recovered symbols applied
  (0 errors)** and saved into the project.
- Export in `build/crunch-analysis/ghidra-export/`: `summary.txt`,
  `interesting-functions.txt` (keyword buckets: login/auth/session/package/
  crunch/update/license/blowfish/webs/ftp…), and decompilations
  `decomp_*.c` for the login, package, crypto, license, remote-client and
  Crunch functions cited in this document.
- The decompiled `Crunch::DeCompressData` in this second, independent binary
  matches the recovered wrapper semantics exactly (arg5==0 → verify
  0x5aa5a55a, read declared size from stream, skip 8-byte header; else
  headerless with arg5 as declared size; error flags at obj+0x20/0x21) —
  third independent confirmation of the RECOVERY.md decoder semantics
  (Unicorn, QEMU, decompilation).
