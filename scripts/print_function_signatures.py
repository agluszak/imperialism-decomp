#@author codex
#@category Analysis

targets = [
    0x005a0c50,  # HandleTacticalBattleCommandTag
    0x005a3c20,  # ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty
    0x0059fdb0,  # FinalizeTacticalTurnStateAndQueueEvent232A
    0x005a55c0,  # TryPlaceTacticalUnitOnTileAndAdvanceSelection
    0x005a5730,  # ResolveTacticalAttackAgainstTileOccupant
    0x005a59a0,  # ConvertHexTileIndexToRowAndDoubleColumn
    0x005a63c0,  # ApplyTacticalDamageAndDeathState
    0x005de990,  # ShowLocalizedUiPromptByGroupAndIndex
]

fm = currentProgram.getFunctionManager()
for t in targets:
    addr = toAddr(t)
    fn = fm.getFunctionAt(addr)
    if fn is None:
        print("0x%08x -> <no function>" % t)
        continue
    print("0x%08x -> %s" % (t, fn.getName()))
    print("  sig: %s" % fn.getSignature(True))
    params = fn.getParameters()
    for i in range(len(params)):
        p = params[i]
        print("    param%d: %s %s" % (i, p.getDataType().getDisplayName(), p.getName()))
