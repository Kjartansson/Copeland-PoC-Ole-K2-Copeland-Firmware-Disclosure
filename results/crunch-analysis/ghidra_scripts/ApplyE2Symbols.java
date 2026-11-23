// Apply recovered VxWorks standalone symbol names to the E2E firmware program.
import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;

public class ApplyE2Symbols extends GhidraScript {
    private static final String SYMBOL_FILE =
        System.getenv().getOrDefault("E2_SYMBOL_FILE", "e2_fw-vxworks-symbols.txt");

    @Override
    public void run() throws Exception {
        int applied = 0;
        int errors = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(SYMBOL_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int sep = line.indexOf(' ');
                if (sep <= 0) {
                    continue;
                }
                Address addr = toAddr(Long.parseUnsignedLong(line.substring(0, sep), 16));
                String name = line.substring(sep + 1).trim();
                if (name.isEmpty()) {
                    continue;
                }
                try {
                    String clean = SymbolUtilities.replaceInvalidChars(name, true);
                    Function existing = getFunctionAt(addr);
                    if (existing != null) {
                        if (!existing.getName().equals(clean)) {
                            existing.setName(clean, SourceType.IMPORTED);
                        }
                    } else {
                        createLabel(addr, clean, true);
                    }
                    applied++;
                } catch (Exception exc) {
                    errors++;
                }
            }
        }
        println("E2 symbols applied=" + applied + " errors=" + errors);
    }
}
