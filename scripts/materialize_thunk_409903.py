#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
a=toAddr(0x00409903)
fn=fm.getFunctionContaining(a)
if fn is None:
    fn=createFunction(a,None)
    print('CREATED',fn.getName() if fn else '<failed>')
else:
    print('EXISTS',fn.getName())
