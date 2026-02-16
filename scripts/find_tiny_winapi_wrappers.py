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

def get_call_target_name(ins):
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

def collect_prev_push_imms(ins, limit=6):
    vals = []
    cur = ins.getPrevious()
    steps = 0
    while cur is not None and steps < limit:
        if cur.getMnemonicString() == "PUSH":
            op = cur.getOpObjects(0)
            if op is not None and len(op) == 1:
                o = op[0]
                s = str(o)
                # keep immediates / constants only
                if s.startswith("0x") or s.startswith("-0x") or s.isdigit():
                    vals.append(s)
        if cur.getFlowType().isCall():
            break
        steps += 1
        cur = cur.getPrevious()
    return vals

print("=== tiny WinAPI wrappers (FUN_*) ===")
count = 0
for fn in fm.getFunctions(True):
    name = fn.getName()
    if not name.startswith("FUN_"):
        continue

    insns = []
    calls = []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        insns.append(ins)
        if ins.getFlowType().isCall():
            calls.append(ins)

    if len(calls) != 1:
        continue
    if len(insns) > 30:
        continue

    call_ins = calls[0]
    tgt = get_call_target_name(call_ins)
    if tgt is None:
        continue

    pushes = collect_prev_push_imms(call_ins, 8)
    print("%s %s -> %s pushes=%s insns=%d" % (
        fn.getEntryPoint(),
        name,
        tgt,
        pushes,
        len(insns),
    ))
    count += 1

print("count=%d" % count)
