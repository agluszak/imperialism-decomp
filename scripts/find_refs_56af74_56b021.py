#@author codex
#@category Analysis
refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()
for t in [0x0056af74,0x0056b021]:
    addr = toAddr(t)
    print('=== refs to %s ===' % addr)
    refs = list(refman.getReferencesTo(addr))
    if not refs:
        print('none')
    for r in refs:
        s = r.getFromAddress()
        fn = fm.getFunctionContaining(s)
        fnn = fn.getName() if fn else '<no_function>'
        print('  from %s type=%s fn=%s' % (s, r.getReferenceType(), fnn))
