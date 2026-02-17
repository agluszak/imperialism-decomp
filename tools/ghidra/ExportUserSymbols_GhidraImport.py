#@category Imperialism
# Exports USER_DEFINED symbols in the common ImportSymbolsScript format:
#   symbolName HEXADDR f|l
#
# f = function
# l = label/data
#
# Supported runtime:
# - Ghidra 12.0.2 PUBLIC only
#
# Notes:
# - Most ImportSymbolsScript variants parse with line.split(), so names with
#   whitespace cannot be imported reliably. This script skips those names.

from ghidra.framework import Application
from ghidra.program.model.symbol import SourceType, SymbolType

EXPECTED_GHIDRA_VERSION = "12.0.2"
EXPECTED_GHIDRA_RELEASE = "PUBLIC"

SKIP_NAMES_WITH_WHITESPACE = True
EXPORT_ONLY_USER_DEFINED = True
EXPORT_ONLY_MEMORY_SYMBOLS = True
EXPORT_ONLY_PRIMARY = True


def enforce_ghidra_version():
    actual_version = Application.getApplicationVersion()
    actual_release = Application.getApplicationReleaseName()
    if (
        actual_version != EXPECTED_GHIDRA_VERSION
        or actual_release != EXPECTED_GHIDRA_RELEASE
    ):
        raise RuntimeError(
            "Unsupported Ghidra runtime: {} {}. Expected {} {}.".format(
                actual_version,
                actual_release,
                EXPECTED_GHIDRA_VERSION,
                EXPECTED_GHIDRA_RELEASE,
            )
        )


enforce_ghidra_version()

args = getScriptArgs()
if args is not None and len(args) >= 1 and args[0]:
    out_path = args[0]
else:
    out_path = askFile("Export symbols to (.ghidra-like text)...", "Save").absolutePath

symtab = currentProgram.getSymbolTable()

rows = []
skipped_ws = 0
skipped_nonmem = 0
skipped_nonuser = 0
skipped_nonprimary = 0

it = symtab.getAllSymbols(True)
while it.hasNext() and not monitor.isCancelled():
    sym = it.next()
    if sym is None:
        continue

    if EXPORT_ONLY_PRIMARY and not sym.isPrimary():
        skipped_nonprimary += 1
        continue

    if EXPORT_ONLY_USER_DEFINED and sym.getSource() != SourceType.USER_DEFINED:
        skipped_nonuser += 1
        continue

    addr = sym.getAddress()
    if EXPORT_ONLY_MEMORY_SYMBOLS and not addr.isMemoryAddress():
        skipped_nonmem += 1
        continue

    name = sym.getName(True)
    if SKIP_NAMES_WITH_WHITESPACE and (
        (" " in name) or ("\t" in name) or ("\r" in name) or ("\n" in name)
    ):
        skipped_ws += 1
        print("Skipping (whitespace in name): {}".format(name))
        continue

    st = sym.getSymbolType()
    kind = "f" if st == SymbolType.FUNCTION else "l"
    rows.append((addr.getOffset(), name, kind))

rows.sort(key=lambda t: (t[0], t[2], t[1]))

num_f = 0
num_l = 0

# Use binary mode and utf-8 so behavior is stable across Python runtimes.
with open(out_path, "wb") as fd:
    for (off, name, kind) in rows:
        if kind == "f":
            num_f += 1
        else:
            num_l += 1
        fd.write(u"{} {:X} {}\n".format(name, off, kind).encode("utf-8"))

print("Wrote {} symbols to {}".format(len(rows), out_path))
print("  functions: {}, labels: {}".format(num_f, num_l))
print("Skipped:")
print("  non-primary: {}".format(skipped_nonprimary))
print("  non-user-defined: {}".format(skipped_nonuser))
print("  non-memory: {}".format(skipped_nonmem))
print("  whitespace names: {}".format(skipped_ws))
