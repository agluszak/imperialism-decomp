#@author codex
#@category Analysis
fm=currentProgram.getFunctionManager()
addrs=[
0x00402e7d,0x00403053,0x004081a7,0x004067e9,0x00406514,0x0040952f,0x00404df4,
0x004068f2,0x00403e81,0x00404c91,0x00401ef6,0x00406ad2,0x00401064,0x004025a9,
0x004057cc,0x004064ba,0x00407ebe,0x00408611,0x00405902,0x00402608
]
for a in addrs:
    addr=toAddr(a)
    fn=fm.getFunctionContaining(addr)
    if fn is None:
        fn=createFunction(addr,None)
        print('CREATE',hex(a),fn.getName() if fn else '<failed>')
    else:
        print('EXIST',hex(a),fn.getName(),fn.getEntryPoint())
