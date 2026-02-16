#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
addrs=[0x00401cdf,0x00401ed8,0x004027f2,0x004094e9,0x004098b8,0x0040691f,0x00407bda,0x00408724]
for a in addrs:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName())
