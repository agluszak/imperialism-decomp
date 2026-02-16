#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
for a in [0x005781f0,0x00575770]:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName(),fn.getEntryPoint())
