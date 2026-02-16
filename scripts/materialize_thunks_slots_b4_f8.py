#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
addrs=[0x00401244,0x004065fa,0x0040731a,0x0040261c,0x004011a9,0x004071ad,0x0040742d,0x004024eb,0x004072d9,0x00402432,0x00404728]
for a in addrs:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName())
