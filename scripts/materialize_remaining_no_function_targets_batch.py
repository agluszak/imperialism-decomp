#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
addrs=[0x005d6e30,0x005d7f70,0x005d7f90,0x005dc180,0x005dc1c0,0x005d7190,0x005dd180,0x005dbd10]
for a in addrs:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName(),fn.getEntryPoint())
