#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
for start, end in [(0x00407240,0x00407260),(0x00408820,0x00408840)]:
    print('RANGE %08X-%08X' % (start,end))
    it = fm.getFunctions(toAddr(start), True)
    found = False
    while it.hasNext():
        fn = it.next()
        entry = fn.getEntryPoint().getOffset()
        if entry > end:
            break
        if start <= entry <= end:
            found = True
            print('  %s @ %s body=%s' % (fn.getName(), fn.getEntryPoint(), fn.getBody()))
    if not found:
        print('  <none>')
