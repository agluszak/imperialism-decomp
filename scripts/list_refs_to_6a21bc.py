#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()

print('=== refs to g_pUiRuntimeContext global 0x006A21BC ===')
seen=set()
for r in getReferencesTo(toAddr(0x006a21bc)):
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    key = (str(src), fnn, str(r.getReferenceType()))
    if key in seen:
        continue
    seen.add(key)
    print('%s | %s | %s' % key)
print('TOTAL=%d' % len(seen))
