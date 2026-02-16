#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
for a in [0x004017b7,0x004094f8]:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName())
