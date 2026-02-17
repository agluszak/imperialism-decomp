#@category Imperialism
# Export USER_DEFINED functions and globals to reccmp CSV (pipe-delimited):
#   address|name|size|type|prototype
#
# Supported runtime:
# - Ghidra 12.0.2 PUBLIC only
#
# Smart function size:
# - insn_bytes = sum(instruction lengths in function body)
# - body_bytes = sum(address-range lengths in function body)
# - export size = insn_bytes if insn_bytes > 0 else body_bytes
#
# reccmp expects:
# - address as hex (0x optional)
# - size as decimal bytes
# - type values such as function/global/string/etc

from ghidra.framework import Application
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

EXPECTED_GHIDRA_VERSION = "12.0.2"
EXPECTED_GHIDRA_RELEASE = "PUBLIC"

EXPORT_ONLY_USER_DEFINED = True
SKIP_NAMES_WITH_WHITESPACE = True


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
    out_path = askFile("Export reccmp CSV to...", "Save").absolutePath

fm = currentProgram.getFunctionManager()
symtab = currentProgram.getSymbolTable()
listing = currentProgram.getListing()


def has_ws(s):
    return (" " in s) or ("\t" in s) or ("\r" in s) or ("\n" in s)


def func_insn_bytes(f):
    total = 0
    it = listing.getInstructions(f.getBody(), True)
    while it.hasNext() and not monitor.isCancelled():
        ins = it.next()
        total += ins.getLength()
    return total


def func_body_bytes(f):
    total = 0
    rng_it = f.getBody().getAddressRanges()
    while rng_it.hasNext() and not monitor.isCancelled():
        r = rng_it.next()
        total += r.getLength()
    return total


def clean_field(s):
    return " ".join(s.replace("|", " ").split())


rows = []
rows.append("address|name|size|type|prototype")

# Functions
funcs = []
itf = fm.getFunctions(True)
while itf.hasNext() and not monitor.isCancelled():
    f = itf.next()
    sym = f.getSymbol()
    if sym is None:
        continue
    if EXPORT_ONLY_USER_DEFINED and sym.getSource() != SourceType.USER_DEFINED:
        continue

    name = f.getName(True)
    if SKIP_NAMES_WITH_WHITESPACE and has_ws(name):
        print("Skipping function (whitespace in name): {}".format(name))
        continue

    entry = f.getEntryPoint()
    insn = func_insn_bytes(f)
    body = func_body_bytes(f)
    size = insn if insn > 0 else body

    proto = clean_field(f.getPrototypeString(True, True))
    funcs.append((entry.getOffset(), name, size, insn, body, proto))

funcs.sort(key=lambda t: t[0])

for (addr, name, size, insn, body, proto) in funcs:
    rows.append("{:x}|{}|{}|function|{}".format(addr, name, size, proto))

# Globals / labels (USER_DEFINED), size left blank.
sym_it = symtab.getAllSymbols(True)
globals_ = []
while sym_it.hasNext() and not monitor.isCancelled():
    s = sym_it.next()
    if s is None:
        continue
    if EXPORT_ONLY_USER_DEFINED and s.getSource() != SourceType.USER_DEFINED:
        continue
    if isinstance(s.getObject(), Function):
        continue

    addr = s.getAddress()
    if not addr.isMemoryAddress():
        continue

    name = s.getName(True)
    if SKIP_NAMES_WITH_WHITESPACE and has_ws(name):
        print("Skipping global (whitespace in name): {}".format(name))
        continue

    globals_.append((addr.getOffset(), name))

globals_.sort(key=lambda t: t[0])
for (addr, name) in globals_:
    rows.append("{:x}|{}||global|".format(addr, name))

with open(out_path, "wb") as fd:
    fd.write(("\n".join(rows) + "\n").encode("utf-8"))

print(
    "Wrote {} function rows and {} global rows to {}".format(
        len(funcs), len(globals_), out_path
    )
)
print("Note: reccmp expects hex address and decimal byte size.")
