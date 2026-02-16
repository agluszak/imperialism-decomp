#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()

targets = [
    0x004813A0,  # A1
    0x00481770,  # A7
    0x00481B30,  # AB
    0x00481DC0,  # AE
    0x00482050,  # B1
    0x0049BCD0,  # D0
    0x005DEE50,  # E0
    0x00480A10,  # 104
]

target_addrs = {toAddr(t): t for t in targets}
hits = {}
for t in target_addrs:
    hits[t] = []

# Single pass through instructions.
it = listing.getInstructions(True)
while it.hasNext():
    ins = it.next()
    if ins.getMnemonicString().upper() != "JMP":
        continue
    for r in ins.getReferencesFrom():
        to = r.getToAddress()
        if to in target_addrs:
            hits[to].append(ins)

for target in sorted(hits.keys(), key=lambda a: int(a.getOffset())):
    print("=== JMP thunks to %s ===" % target)
    found = hits[target]
    if not found:
        print("none")
        continue
    for ins in found:
        a = ins.getAddress()
        fn = fm.getFunctionContaining(a)
        fn_name = fn.getName() if fn else "<no_function>"
        fn_entry = fn.getEntryPoint() if fn else a
        print("  %s | %s | %s" % (a, fn_name, ins))
        refs = list(rm.getReferencesTo(fn_entry))
        if not refs:
            print("    no refs to thunk entry")
            continue
        for x in refs:
            src = x.getFromAddress()
            sfn = fm.getFunctionContaining(src)
            sfn_name = sfn.getName() if sfn else "<no_function>"
            print("    ref from %s type=%s fn=%s" % (src, x.getReferenceType(), sfn_name))
    print("")
