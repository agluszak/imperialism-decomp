#@author codex
#@category Analysis

listing = currentProgram.getListing()
refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

targets = [0x0048542a,0x00485910,0x00413d20,0x00414720]
for t in targets:
    print('=== JMP thunks to %08x ===' % t)
    found = []
    for ins in listing.getInstructions(True):
        if ins.getMnemonicString().upper() != 'JMP':
            continue
        txt = str(ins).lower()
        if ('0x%08x' % t) in txt:
            found.append(ins)
    if not found:
        print('none')
        continue
    for ins in found:
        a = ins.getAddress()
        fn = fm.getFunctionContaining(a)
        fn_name = fn.getName() if fn else '<no_function>'
        print('  %s | %s | %s' % (a, fn_name, ins))
        refs = list(refman.getReferencesTo(a))
        for r in refs[:10]:
            s = r.getFromAddress()
            sfn = fm.getFunctionContaining(s)
            sfn_name = sfn.getName() if sfn else '<no_function>'
            print('    ref from %s type=%s fn=%s' % (s, r.getReferenceType(), sfn_name))
        if len(refs) > 10:
            print('    ... +%d more refs' % (len(refs)-10))
    print('')
