// Export targeted analysis of the recovered E2E 4.11F03 firmware:
// function counts, interesting function addresses, and decompilation of
// selected functions to build/crunch-analysis/ghidra-export/.
import java.io.File;
import java.io.FileWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportE2Analysis extends GhidraScript {
    private static final String OUT =
        System.getenv().getOrDefault("E2_EXPORT_DIR", "ghidra-export");
    private static final String[] KEYWORDS = {
        "login", "password", "passwd", "auth", "session", "credential",
        "package", "crunch", "update", "upgrade", "license", "blowfish",
        "md5", "webs", "realm", "ftp", "telnet", "crypto", "key" };
    private static final String[] TARGETS = {
        "cpcLoginSession", "cpcGetSessionUsername",
        "_ZN14AccessServices11GetUserDataEPcS0_RhRmPt",
        "_ZN14AccessServices26CalculateSalPasswordEhhhPc",
        "_ZN16E2FirmwareUpdate15validatePackageEv",
        "_ZN16E2FirmwareUpdate23validatePackageContentsEv",
        "_ZN16E2FirmwareUpdate5ApplyEv",
        "_ZN16E2FirmwareUpdate8TransferEv",
        "_ZN10CpcPackage6unpackEv",
        "_ZN10CpcPackage23validatePackageContentsEv",
        "_ZN10CpcPackage24unpackToNativeFileSystemESsSs",
        "_ZN6Crunch14DeCompressDataEPvmS0_",
        "_ZN13CpcEncryption11DecryptDataEPhRm",
        "_ZN13CpcEncryption26concatenateEncryptionKeyEPc",
        "_ZN17CpcLicenseManager15activateFeatureEPhc",
        "_Z23CpcValidateRemoteClientP12EXPLICIT_MSG",
        "websGetRealm", "websSetRealm",
        "_ZN9CpcE2Peer11sendMessageEP6CpcMsg" };

    @Override
    public void run() throws Exception {
        new File(OUT).mkdirs();
        Map<String, Function> byName = new HashMap<>();
        Map<String, Integer> counts = new TreeMap<>();
        StringBuilder interesting = new StringBuilder();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();
            total++;
            byName.putIfAbsent(f.getName(), f);
        }
        try (FileWriter w = new FileWriter(OUT + "/summary.txt")) {
            w.write("functions=" + total + "\n");
        }
        for (String kw : KEYWORDS) {
            StringBuilder sb = new StringBuilder();
            int n = 0;
            for (Map.Entry<String, Function> e : byName.entrySet()) {
                if (e.getKey().toLowerCase().contains(kw) && n < 60) {
                    sb.append(String.format("  %s %s%n", e.getValue().getEntryPoint(), e.getKey()));
                    n++;
                }
            }
            counts.put(kw, n);
            interesting.append("== ").append(kw).append(" (").append(n).append(")\n").append(sb);
        }
        try (FileWriter w = new FileWriter(OUT + "/interesting-functions.txt")) {
            w.write(interesting.toString());
        }
        println("functions=" + total);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (String target : TARGETS) {
            Function f = byName.get(target);
            if (f == null) {
                for (Map.Entry<String, Function> e : byName.entrySet()) {
                    if (e.getKey().toLowerCase().contains(target.toLowerCase())) {
                        f = e.getValue();
                        break;
                    }
                }
            }
            if (f == null) {
                println("target not found: " + target);
                continue;
            }
            DecompileResults res = decomp.decompileFunction(f, 120, monitor);
            String path = OUT + "/decomp_" + target.replaceAll("[^A-Za-z0-9_.-]", "_") + ".c";
            try (FileWriter w = new FileWriter(path)) {
                if (res.getDecompiledFunction() != null) {
                    w.write(res.getDecompiledFunction().getC());
                } else {
                    w.write("// decompile failed: " + res.getErrorMessage() + "\n");
                }
            }
            println("decompiled " + target);
        }
        decomp.dispose();
        println("export done -> " + OUT);
    }
}
