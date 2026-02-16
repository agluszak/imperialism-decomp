#@author codex
#@category Analysis

targets = [
    0x005a55c0,  # TryPlaceTacticalUnitOnTileAndAdvanceSelection
    0x005a5730,  # ResolveTacticalAttackAgainstTileOccupant
    0x005a3c20,  # ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty
]

fm = currentProgram.getFunctionManager()
for t in targets:
    addr = toAddr(t)
    fn = fm.getFunctionAt(addr)
    if fn is None:
        print("0x%08x -> <no function>" % t)
        continue
    print("0x%08x -> %s" % (t, fn.getName()))
    vars_all = fn.getAllVariables()
    for v in vars_all:
        print("  %s : %s [%s]" % (v.getName(), v.getDataType().getDisplayName(), v.getVariableStorage()))
