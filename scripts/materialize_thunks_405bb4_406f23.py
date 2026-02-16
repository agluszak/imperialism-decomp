#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
for a in [0x00405bb4,0x00406f23]:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName())
