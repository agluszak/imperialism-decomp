#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager()
print('=== refs to 0x006A21BC grouped by function ===')
seen={}
for r in getReferencesTo(toAddr(0x006a21bc)):
    src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
    seen.setdefault(fnn,0)
    seen[fnn]+=1
for fnn in sorted(seen.keys()):
    print('%s | refs=%d' % (fnn, seen[fnn]))
print('TOTAL_FUNCTIONS=%d' % len(seen))
