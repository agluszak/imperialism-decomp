#@author codex
#@category Analysis

listing=currentProgram.getListing(); mem=currentProgram.getMemory(); sym=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager(); fm=currentProgram.getFunctionManager()
start=0x0064d100; end=0x0064d170
print('=== dwords %08x-%08x ===' % (start,end))
for a in range(start,end,4):
    addr=toAddr(a)
    try:
        val=mem.getInt(addr) & 0xffffffff
    except:
        continue
    s=sym.getPrimarySymbol(toAddr(val))
    fn=fm.getFunctionContaining(toAddr(val))
    nm = s.getName() if s else (fn.getName() if fn else '')
    print('%s -> %08x %s' % (addr,val,nm))
print('=== refs to 0064d13c ===')
for r in ref.getReferencesTo(toAddr(0x0064d13c)):
    src=r.getFromAddress(); fn=fm.getFunctionContaining(src)
    print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn.getName() if fn else '<none>'))
