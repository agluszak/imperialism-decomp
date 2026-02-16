#@author codex
#@category Analysis

listing = currentProgram.getListing()
refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

targets = [0x0048542a,0x00485910,0x00480500,0x0047f8b0]
for t in targets:
    addr = toAddr(t)
    print('=== refs to %s ===' % addr)
    refs = list(refman.getReferencesTo(addr))
    if not refs:
        print('none')
    for r in refs:
        src = r.getFromAddress()
        fn = fm.getFunctionContaining(src)
        name = fn.getName() if fn else '<no_function>'
        print('  from %s type=%s fn=%s' % (src, r.getReferenceType(), name))
    print('')
