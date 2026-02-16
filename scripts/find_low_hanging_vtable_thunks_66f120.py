#@author codex
#@category Analysis

listing = currentProgram.getListing()
mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

VT = 0x0066f120
N = 64

print('=== low-hanging thunk candidates from PTR_LAB_0066f120 ===')
for i in range(N):
    vt_addr = toAddr(VT + i*4)
    try:
        ptr = mem.getInt(vt_addr) & 0xffffffff
    except:
        continue
    ea = toAddr(ptr)
    fn = fm.getFunctionContaining(ea)
    ins = listing.getInstructionAt(ea)
    if ins is None:
        ins = listing.getInstructionContaining(ea)
    if ins is None:
        continue

    mnem = ins.getMnemonicString().upper()
    if mnem != 'JMP':
        continue

    flows = ins.getFlows()
    if flows is None or len(flows) == 0:
        continue

    tgt = flows[0]
    tgt_fn = fm.getFunctionContaining(tgt)
    tgt_name = tgt_fn.getName() if tgt_fn else '<no_function>'
    fn_name = fn.getName() if fn else '<no_function>'

    # count short body length if function exists
    body_len = -1
    if fn is not None:
        c = 0
        it = listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            it.next(); c += 1
        body_len = c

    print('slot=%02d vt=%s entry=%s fn=%s body_ins=%d jmp=%s tgt_fn=%s' % (
        i, vt_addr, ea, fn_name, body_len, tgt, tgt_name
    ))

print('=== done ===')
