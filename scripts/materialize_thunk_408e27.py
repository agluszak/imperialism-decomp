#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager(); a=toAddr(0x00408e27)
fn=fm.getFunctionContaining(a)
if fn is None:
    fn=createFunction(a,None)
    print('CREATE',fn.getName() if fn else '<failed>')
else:
    print('EXIST',fn.getName())
