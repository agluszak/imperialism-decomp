#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

start=toAddr(0x004a9960); end=toAddr(0x004a9b20)
print('=== region 0x004A9960..0x004A9B20 ===')
ins=listing.getInstructionAt(start)
while ins and ins.getAddress().compareTo(end)<=0:
    fn=fm.getFunctionContaining(ins.getAddress())
    fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
    ins=ins.getNext()
print('=== done ===')
