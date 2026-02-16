#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()

points=[0x004a9a3e,0x0050ed78,0x005d70a2,0x005d7c4e,0x0041464a,0x0049ccc8]
for p in points:
    addr=toAddr(p)
    fn=fm.getFunctionContaining(addr)
    print('0x%08x | fn=%s' % (p, fn.getName() if fn else '<none>'))
    ins=listing.getInstructionAt(addr)
    print('  ins=%s' % (ins if ins else '<none>'))
