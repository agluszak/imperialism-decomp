#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

APPLY = False
MAX_INSNS = 8

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()

renames = []

for fn in fm.getFunctions(True):
    old_name = fn.getName()
    if not old_name.startswith("thunk_FUN_"):
        continue

    insns = []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext() and len(insns) < MAX_INSNS:
        insns.append(it.next())

    if len(insns) == 0:
        continue

    flow_target = None
    for ins in insns:
        mnem = ins.getMnemonicString()
        if mnem not in ("CALL", "JMP"):
            continue
        for ref in ins.getReferencesFrom():
            if not ref.getReferenceType().isFlow():
                continue
            flow_target = ref.getToAddress()
            break
        if flow_target is not None:
            break

    if flow_target is None:
        continue

    callee = fm.getFunctionContaining(flow_target)
    if callee is None:
        continue

    callee_name = callee.getName()
    if callee_name.startswith("FUN_") or callee_name.startswith("thunk_"):
        continue

    new_name = "thunk_" + callee_name
    if new_name == old_name:
        continue

    existing = st.getGlobalSymbol(new_name, fn.getEntryPoint())
    if existing is not None and existing.getAddress() != fn.getEntryPoint():
        continue

    renames.append((fn, old_name, new_name, callee_name))

print("=== thunk_FUN_ wrapper rename candidates ===")
for _, old_name, new_name, callee_name in renames:
    print("%s -> %s (target=%s)" % (old_name, new_name, callee_name))

print("candidate_count=%d apply=%s" % (len(renames), str(APPLY)))

if APPLY:
    for fn, old_name, new_name, _ in renames:
        try:
            fn.setName(new_name, SourceType.USER_DEFINED)
            print("renamed: %s -> %s" % (old_name, new_name))
        except Exception as e:
            print("rename_failed: %s -> %s (%s)" % (old_name, new_name, str(e)))
