#@author codex
#@category Analysis

refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

targets = [
    0x004CE480, # CreateBuildingExpansionView
    0x004CECE0, # CreateArmoryView
    0x004D04B0, # CreateEngineerDialog
    0x004CE500, # GetBuildingExpansionViewClassName
    0x004CED80, # GetArmoryViewClassName
    0x004D0540, # GetEngineerDialogClassName
]

for t in targets:
    addr = toAddr(t)
    fn = fm.getFunctionAt(addr)
    fn_name = fn.getName() if fn else '<no_function>'
    print('=== refs to %s (%s) ===' % (addr, fn_name))
    refs = list(refman.getReferencesTo(addr))
    if not refs:
        print('none')
    for r in refs:
        src = r.getFromAddress()
        cfn = fm.getFunctionContaining(src)
        cfn_name = cfn.getName() if cfn else '<no_function>'
        print('  from %s type=%s fn=%s' % (src, r.getReferenceType(), cfn_name))
    print('')
