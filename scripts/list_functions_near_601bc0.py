#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
start = toAddr(0x00601B00)
end = 0x00601D00

it = fm.getFunctions(start, True)
print('=== functions near 0x00601BC0 ===')
while it.hasNext():
    fn = it.next()
    off = fn.getEntryPoint().getOffset()
    if off >= end:
        break
    print('%s %s' % (fn.getEntryPoint(), fn.getName()))
