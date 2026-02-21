#@category Imperialism/Stats

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()

total = 0
user_defined = 0
non_generic = 0

it = fm.getFunctions(True)
while it.hasNext():
    fn = it.next()
    total += 1

    sym = fn.getSymbol()
    if sym is not None and sym.getSource() == SourceType.USER_DEFINED:
        user_defined += 1

    name = fn.getName()
    if not name.startswith("FUN_") and not name.startswith("thunk_FUN_"):
        non_generic += 1

print("PROGRAM=%s" % currentProgram.getName())
print("TOTAL_FUNCTIONS=%d" % total)
print("USER_DEFINED_FUNCTION_SYMBOLS=%d" % user_defined)
print("NON_GENERIC_NAMES=%d" % non_generic)
