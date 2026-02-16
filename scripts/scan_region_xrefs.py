#@author codex
#@category Analysis

refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

regions=[(0x0069c900,0x0069ca00,'data69c9'),(0x0067ef00,0x0067f000,'rdata67ef')]
for start,end,name in regions:
    print('=== xrefs in %s %08x-%08x ===' % (name,start,end))
    total=0
    for a in range(start,end,4):
        addr=toAddr(a)
        refs=list(refman.getReferencesTo(addr))
        if refs:
            total+=1
            print('%s refs=%d' % (addr,len(refs)))
            for r in refs[:6]:
                src=r.getFromAddress()
                fn=fm.getFunctionContaining(src)
                fn_name=fn.getName() if fn else '<no_function>'
                print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn_name))
            if len(refs)>6:
                print('  ... +%d more' % (len(refs)-6))
    print('ADDRS_WITH_REFS=%d\n' % total)
