# Export targeted analysis of the recovered E2E 4.11F03 firmware:
# function inventory counts, interesting function addresses, xrefs to
# credential/update/crypto strings, and decompilation of selected functions.
# Jython (Ghidra headless -postScript).
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.environ.get("E2_EXPORT_DIR", os.path.abspath("ghidra-export"))
if not os.path.isdir(OUT):
    os.makedirs(OUT)

program = getCurrentProgram()
fm = program.getFunctionManager()
listing = program.getListing()

func_count = fm.getFunctionCount()
with open(os.path.join(OUT, "summary.txt"), "w") as handle:
    handle.write("functions=%d\n" % func_count)

KEYWORDS = ["login", "password", "passwd", "auth", "session", "credential",
            "package", "crunch", "update", "upgrade", "license", "blowfish",
            "md5", "webs", "realm", "ftp", "telnet", "crypto", "key"]
interesting = {}
iter_funcs = fm.getFunctions(True)
for f in iter_funcs:
    lname = f.getName().lower()
    for kw in KEYWORDS:
        if kw in lname:
            interesting.setdefault(kw, []).append((f.getEntryPoint().getOffset(),
                                                   f.getName()))
with open(os.path.join(OUT, "interesting-functions.txt"), "w") as handle:
    for kw in KEYWORDS:
        rows = interesting.get(kw, [])
        handle.write("== %s (%d)\n" % (kw, len(rows)))
        for addr, name in sorted(rows)[:60]:
            handle.write("  0x%08x %s\n" % (addr, name))

TARGETS = [
    "cpcLoginSession", "cpcGetSessionUsername",
    "cpcValidateUser", "cpcGetUserAccess",
    "_ZN16E2FirmwareUpdate15validatePackageEv",
    "_ZN16E2FirmwareUpdate23validatePackageContentsEv",
    "_ZN16E2FirmwareUpdate5ApplyEv",
    "_ZN16E2FirmwareUpdate8TransferEv",
    "_ZN10CpcPackage6unpackEv",
    "_ZN10CpcPackage23validatePackageContentsEv",
    "_ZN10CpcPackage24unpackToNativeFileSystemESsSs",
    "_ZN6Crunch14DeCompressDataEPvmS0_",
    "_ZN17CpcLicenseManager15activateFeatureEPhc",
    "websGetRealm", "websSetRealm",
]
byname = {}
iter_funcs = fm.getFunctions(True)
for f in iter_funcs:
    byname.setdefault(f.getName(), f)

decomp = DecompInterface()
decomp.openProgram(program)
monitor = ConsoleTaskMonitor()
for target in TARGETS:
    f = byname.get(target)
    if f is None:
        # substring fallback
        for name, cand in byname.items():
            if target.lower() in name.lower():
                f = cand
                break
    if f is None:
        print("target not found:", target)
        continue
    res = decomp.decompileFunction(f, 120, monitor)
    out = os.path.join(OUT, "decomp_%s.c" % target.replace("/", "_"))
    with open(out, "w") as handle:
        if res.decompiledFunction is not None:
            handle.write(res.decompiledFunction.getC())
        else:
            handle.write("// decompile failed: %s\n" % res.getErrorMessage())
    print("decompiled", target, "->", out)

# string xrefs for a few security-relevant strings
WANT = ["WWW-Authenticate", "530 Login required", "230 Login OK",
        "FAILED WRITE ON SYSUPDATE", "/JSON-RPC", "E2.ClientLogin",
        "Ready for firmware update", "/ata00:2/e2_fw.pkg"]
data_iter = listing.getDefinedData(True)
with open(os.path.join(OUT, "string-xrefs.txt"), "w") as handle:
    for d in data_iter:
        try:
            val = d.getValue()
        except Exception:
            continue
        if not isinstance(val, str):
            continue
        for want in WANT:
            if want in val:
                refs = d.getReferenceIteratorTo()
                ref_list = [str(r.getFromAddress()) for r in refs]
                handle.write("%s @ %s refs=%s\n" % (repr(val[:80]),
                                                    d.getAddress(), ref_list))
decomp.dispose()
print("export done ->", OUT)
