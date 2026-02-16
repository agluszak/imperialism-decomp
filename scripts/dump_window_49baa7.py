#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

t = toAddr(0x0049BAA7)
ins = listing.getInstructionContaining(t)
print('target ins:', ins)
fn = fm.getFunctionContaining(t)
print('containing fn:', fn.getName() if fn else '<none>')

if ins:
    cur = ins
    for _ in range(30):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p
    print('=== window ===')
    for _ in range(100):
        if cur is None:
            break
        a = cur.getAddress()
        cfn = fm.getFunctionContaining(a)
        cname = cfn.getName() if cfn else '<none>'
        print('%s: %-40s ; fn=%s' % (a, str(cur), cname))
        cur = cur.getNext()
