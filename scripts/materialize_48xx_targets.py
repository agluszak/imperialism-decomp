#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager()
for x in [0x0048abc0,0x0048b1a0,0x0048b250,0x0048c050]:
    a=toAddr(x)
    fn=fm.getFunctionContaining(a)
    if fn is None:
        fn=createFunction(a,None)
        print('CREATE',a,fn.getName() if fn else None)
    else:
        print('EXIST',a,fn.getName())
