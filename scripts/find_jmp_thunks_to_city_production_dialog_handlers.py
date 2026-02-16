#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()

targets = {
    toAddr(0x004CE5A0): "OpenCityViewProductionDialog",
    toAddr(0x004CEBB0): "ApplyCityProductionDialogChanges",
}
hits = {k: [] for k in targets.keys()}

it = listing.getInstructions(True)
while it.hasNext():
    ins = it.next()
    if ins.getMnemonicString().upper() != "JMP":
        continue
    for r in ins.getReferencesFrom():
        to = r.getToAddress()
        if to in hits:
            hits[to].append(ins)

for tgt, name in sorted(hits.items(), key=lambda kv: int(kv[0].getOffset())):
    print("=== JMP thunks to %s (%s) ===" % (targets[tgt], tgt))
    if not name:
        print("none")
        continue
    for ins in name:
        a = ins.getAddress()
        fn = fm.getFunctionContaining(a)
        fn_name = fn.getName() if fn else "<no_function>"
        fn_entry = fn.getEntryPoint() if fn else a
        print("  %s | %s | %s" % (a, fn_name, ins))
        for xr in rm.getReferencesTo(fn_entry):
            src = xr.getFromAddress()
            sfn = fm.getFunctionContaining(src)
            sfn_name = sfn.getName() if sfn else "<no_function>"
            print("    ref from %s type=%s fn=%s" % (src, xr.getReferenceType(), sfn_name))
    print("")
