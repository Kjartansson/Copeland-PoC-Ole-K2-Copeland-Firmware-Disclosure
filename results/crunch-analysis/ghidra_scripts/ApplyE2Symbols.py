# Apply recovered VxWorks standalone symbol names to the E2E firmware program.
# Jython (Ghidra headless -postScript).
import os
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import SymbolUtilities

SYMBOL_FILE = os.environ.get("E2_SYMBOL_FILE", os.path.abspath("e2_fw-vxworks-symbols.txt"))

program = getCurrentProgram()
fm = program.getFunctionManager()
st = program.getSymbolTable()
applied = 0
errors = 0
with open(SYMBOL_FILE) as handle:
    for line in handle:
        parts = line.rstrip("\n").split(" ", 1)
        if len(parts) != 2:
            continue
        addr = toAddr(int(parts[0], 16))
        name = parts[1]
        try:
            clean = SymbolUtilities.replaceInvalidChars(name, True)
            existing = fm.getFunctionAt(addr)
            if existing is not None:
                if existing.getName() != clean:
                    existing.setName(clean, SourceType.IMPORTED)
            else:
                f = fm.getFunctionContaining(addr)
                if f is not None and f.getEntryPoint().equals(addr):
                    f.setName(clean, SourceType.IMPORTED)
                else:
                    createLabel(addr, clean, True)
            applied += 1
        except Exception as exc:
            errors += 1
print("E2 symbols applied=%d errors=%d" % (applied, errors))
