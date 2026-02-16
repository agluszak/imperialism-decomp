#@author codex
#@category Analysis

MAX_INSNS = 8

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()

def get_target_from_wrapper(fn):
    insns = []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext() and len(insns) < MAX_INSNS:
        insns.append(it.next())
    if len(insns) == 0:
        return None

    flow_insn = None
    flow_target = None
    for ins in insns:
        if ins.getMnemonicString() not in ("CALL", "JMP"):
            continue
        for ref in ins.getReferencesFrom():
            if ref.getReferenceType().isFlow():
                flow_insn = ins
                flow_target = ref.getToAddress()
                break
        if flow_target is not None:
            break
    if flow_target is None:
        return None

    callee = fm.getFunctionContaining(flow_target)
    if callee is None:
        return None

    # strict wrapper shape: flow + RET only
    allowed = set(["CALL", "JMP", "RET", "NOP"])
    for ins in insns:
        if ins.getMnemonicString() not in allowed:
            return None

    return callee

rows = []
for fn in fm.getFunctions(True):
    old_name = fn.getName()
    if not old_name.startswith("FUN_"):
        continue
    callee = get_target_from_wrapper(fn)
    if callee is None:
        continue
    callee_name = callee.getName()
    if callee_name.startswith("FUN_"):
        continue
    new_name = "thunk_" + callee_name
    sym = st.getGlobalSymbol(new_name, fn.getEntryPoint())
    collision = (sym is not None and sym.getAddress() != fn.getEntryPoint())
    rows.append((fn.getEntryPoint(), old_name, new_name, callee_name, collision))

print("=== FUN_ wrapper candidates -> thunk_<target> ===")
for addr, old_name, new_name, callee_name, collision in rows:
    print(
        "%s %s -> %s (target=%s)%s"
        % (
            addr,
            old_name,
            new_name,
            callee_name,
            " [name_collision]" if collision else "",
        )
    )

print("candidate_count=%d" % len(rows))
