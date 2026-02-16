#@author codex
#@category Analysis
fm = currentProgram.getFunctionManager()
start = toAddr('0x005001f0')
end = toAddr('0x00500230')
it = fm.getFunctions(start, True)
while it.hasNext():
    fn = it.next()
    ep = fn.getEntryPoint()
    if ep.compareTo(end) > 0:
        break
    if ep.compareTo(start) >= 0:
        print('%s @ %s body=%s' % (fn.getName(), ep, fn.getBody()))
