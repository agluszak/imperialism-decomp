#@author codex
#@category Analysis

mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
VT=0x0066f120
N=64
print('slot,thunk_addr,thunk_name,target_addr,target_name,target_ins')
for i in range(N):
    vt=toAddr(VT+i*4)
    try:
        t=mem.getInt(vt) & 0xffffffff
    except:
        continue
    ta=toAddr(t)
    tf=fm.getFunctionContaining(ta)
    tname=tf.getName() if tf else '<none>'
    ins=listing.getInstructionAt(ta)
    if ins and ins.getMnemonicString().upper()=='JMP':
        flows=ins.getFlows()
        if flows and len(flows)>0:
            tgt=flows[0]
            fn=fm.getFunctionContaining(tgt)
            nm=fn.getName() if fn else '<none>'
            cnt=-1
            if fn:
                c=0
                it=listing.getInstructions(fn.getBody(), True)
                while it.hasNext(): it.next(); c+=1
                cnt=c
            if nm.startswith('FUN_') or nm.startswith('thunk_FUN_') or nm=='<none>' or tname.startswith('thunk_FUN_'):
                print('%02d,0x%08x,%s,0x%08x,%s,%d' % (i,t,tname,tgt.getOffset(),nm,cnt))
        continue
    cnt=-1
    if tf:
        c=0
        it=listing.getInstructions(tf.getBody(), True)
        while it.hasNext(): it.next(); c+=1
        cnt=c
    if tname.startswith('FUN_') or tname.startswith('thunk_FUN_') or tname=='<none>':
        print('%02d,0x%08x,%s,0x%08x,%s,%d' % (i,t,tname,t,tname,cnt))
