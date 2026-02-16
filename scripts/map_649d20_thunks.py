#@author codex
#@category Analysis

listing=currentProgram.getListing()
fm=currentProgram.getFunctionManager()
addrs=[0x004088b4,0x00405b82,0x00406014,0x004053c6,0x0040993a,0x00408b07,0x004046d3,0x00404593,0x00408274,0x00406604,0x00404de0,0x00408350,0x00404e3a]
print('=== map 649d20 entry targets ===')
for aint in addrs:
    a=toAddr(aint)
    ins=listing.getInstructionAt(a)
    txt=str(ins) if ins else '<none>'
    target=None
    if ins and ins.getMnemonicString().upper()=='JMP' and '0x' in txt.lower():
        low=txt.lower()
        hx=low.split('0x',1)[1].split()[0]
        hx=''.join(ch for ch in hx if ch in '0123456789abcdef')
        try:
            target=int(hx,16)
        except:
            target=None
    if target is not None:
        t=toAddr(target)
        fn=fm.getFunctionContaining(t)
        name=fn.getName() if fn else '<no_function>'
        print('%s: %s -> %s (%s)'%(a,txt,t,name))
    else:
        print('%s: %s'%(a,txt))
