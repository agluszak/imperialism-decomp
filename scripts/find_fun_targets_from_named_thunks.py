#@author codex
#@category Analysis

MAX_INSNS = 8

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()

mapping = {}
conflicts = {}

for fn in fm.getFunctions(True):
    thunk_name = fn.getName()
    if not thunk_name.startswith("thunk_"):
        continue
    if thunk_name.startswith("thunk_FUN_"):
        continue

    target_name = thunk_name[len("thunk_") :]
    if target_name == "":
        continue

    insns = []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext() and len(insns) < MAX_INSNS:
        insns.append(it.next())

    flow_target = None
    for ins in insns:
        if ins.getMnemonicString() not in ("CALL", "JMP"):
            continue
        for ref in ins.getReferencesFrom():
            if ref.getReferenceType().isFlow():
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
    if not callee_name.startswith("FUN_"):
        continue

    key = callee.getEntryPoint().toString()
    if key in mapping and mapping[key]["target_name"] != target_name:
        conflicts[key] = [mapping[key]["target_name"], target_name]
        continue
    mapping[key] = {
        "callee": callee,
        "callee_name": callee_name,
        "target_name": target_name,
        "thunk_name": thunk_name,
        "thunk_addr": fn.getEntryPoint(),
    }

print("=== FUN_ targets inferred from named thunks ===")
for key in sorted(mapping.keys()):
    row = mapping[key]
    callee = row["callee"]
    new_name = row["target_name"]
    sym = st.getGlobalSymbol(new_name, callee.getEntryPoint())
    collision = (sym is not None and sym.getAddress() != callee.getEntryPoint())
    if key in conflicts:
        continue
    print(
        "%s %s -> %s (via %s @ %s)%s"
        % (
            callee.getEntryPoint(),
            row["callee_name"],
            new_name,
            row["thunk_name"],
            row["thunk_addr"],
            " [name_collision]" if collision else "",
        )
    )

print("candidate_count=%d conflict_count=%d" % (len(mapping), len(conflicts)))
