#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()

target = toAddr(0x004851b0)  # ShowCityViewSelectionDialog

print("=== JMP thunks to ShowCityViewSelectionDialog (0x004851b0) ===")
count = 0
ins_iter = listing.getInstructions(True)
while ins_iter.hasNext():
    ins = ins_iter.next()
    if ins.getMnemonicString().upper() != "JMP":
        continue
    refs = ins.getReferencesFrom()
    for r in refs:
        if r.getToAddress() != target:
            continue
        fn = fm.getFunctionContaining(ins.getAddress())
        fn_name = fn.getName() if fn else "<no_function>"
        fn_entry = fn.getEntryPoint() if fn else ins.getAddress()
        print("%s | fn=%s entry=%s | %s" % (ins.getAddress(), fn_name, fn_entry, ins))
        for xr in rm.getReferencesTo(fn_entry):
            src = xr.getFromAddress()
            sfn = fm.getFunctionContaining(src)
            sfn_name = sfn.getName() if sfn else "<no_function>"
            print("  ref from %s type=%s fn=%s" % (src, xr.getReferenceType(), sfn_name))
        count += 1

print("count=%d" % count)
