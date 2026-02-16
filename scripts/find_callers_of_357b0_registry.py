#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

for tgt in [0x004357b0,0x00491cc0,0x00491d80,0x0048cfd0]:
    print('=== refs to 0x%08x ===' % tgt)
    for r in getReferencesTo(toAddr(tgt)):
        src = r.getFromAddress()
        fn = fm.getFunctionContaining(src)
        fnn = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
