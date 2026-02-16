#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

t = toAddr(0x0049C120)
ins = listing.getInstructionContaining(t)
cur = ins
for _ in range(20):
    p = cur.getPrevious()
    if p is None: break
    cur = p
print('=== window around 0x0049C120 ===')
for _ in range(80):
    if cur is None: break
    a = cur.getAddress()
    fn = fm.getFunctionContaining(a)
    name = fn.getName() if fn else '<none>'
    print('%s: %-35s ; fn=%s' % (a, str(cur), name))
    cur = cur.getNext()
