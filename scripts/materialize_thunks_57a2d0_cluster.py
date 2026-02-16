#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
for a in [0x004039ef,0x00403b75,0x00407446]:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName())
