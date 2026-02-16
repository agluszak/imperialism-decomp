#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

hits = [0x0067ef0c,0x0069c968]
for h in hits:
    print('=== references to data hit 0x%08x ===' % h)
    for r in getReferencesTo(toAddr(h)):
        src = r.getFromAddress()
        fn = fm.getFunctionContaining(src)
        fnn = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
