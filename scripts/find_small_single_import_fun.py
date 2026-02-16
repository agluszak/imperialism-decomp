#@author codex
#@category Analysis

TARGET_IMPORTS = set([
    "SendMessageA",
    "PostMessageA",
    "ShowWindow",
    "SetWindowPos",
    "LoadCursorA",
    "LoadIconA",
    "UpdateWindow",
])

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()

def call_import_name(ins):
    for ref in ins.getReferencesFrom():
        if not ref.getReferenceType().isCall():
            continue
        to_addr = ref.getToAddress()
        if to_addr is None:
            continue
        syms = st.getSymbols(to_addr)
        for s in syms:
            n = s.getName()
            if n in TARGET_IMPORTS:
                return n
    return None

def prev_push_imms(ins, limit=8):
    vals = []
    cur = ins.getPrevious()
    steps = 0
    while cur is not None and steps < limit:
        if cur.getMnemonicString() == "PUSH":
            op = cur.getOpObjects(0)
            if op is not None and len(op) == 1:
                s = str(op[0])
                if s.startswith("0x") or s.startswith("-0x") or s.isdigit():
                    vals.append(s)
        if cur.getFlowType().isCall():
            break
        cur = cur.getPrevious()
        steps += 1
    return vals

rows = []
for fn in fm.getFunctions(True):
    name = fn.getName()
    if not name.startswith("FUN_"):
        continue
    imports = []
    call_infos = []
    insn_count = 0
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        insn_count += 1
        if ins.getFlowType().isCall():
            imp = call_import_name(ins)
            if imp is not None:
                imports.append(imp)
                call_infos.append((ins.getAddress(), imp, prev_push_imms(ins, 8)))
    if len(imports) == 0:
        continue
    unique = sorted(list(set(imports)))
    if len(unique) != 1:
        continue
    if insn_count > 80:
        continue
    rows.append((fn.getEntryPoint(), name, insn_count, unique[0], call_infos))

rows.sort(key=lambda r: (r[3], r[2], r[1]))

print("=== small FUN_* single-import wrappers (<=80 insns) ===")
for addr, name, icount, imp, infos in rows:
    print("%s %s insns=%d import=%s calls=%d" % (addr, name, icount, imp, len(infos)))
    for caddr, cimp, pushes in infos:
        print("  call@%s pushes=%s" % (caddr, pushes))
print("count=%d" % len(rows))
