#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== writes to [g_dispatch_ctx + 0x4] candidates ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    low = txt.lower()
    mnem = ins.getMnemonicString().upper()
    if mnem not in ('MOV', 'MOVZX', 'MOVSX', 'ADD', 'SUB', 'OR', 'AND', 'XOR'):
        continue
    # memory destination heuristic: instruction starts with mnemonic and first operand is memory +0x4
    if '[eax + 0x4]' not in low and '[ecx + 0x4]' not in low and '[edx + 0x4]' not in low and '[esi + 0x4]' not in low and '[edi + 0x4]' not in low:
        continue

    # require nearby load from 0x006a21bc
    prev = ins.getPrevious()
    window = []
    hit = False
    for _ in range(10):
        if prev is None:
            break
        ptxt = str(prev)
        window.append((prev.getAddress(), ptxt))
        if '0x006a21bc' in ptxt.lower():
            hit = True
        prev = prev.getPrevious()
    if not hit:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, txt))
    for a, t in reversed(window[:8]):
        print('  %s: %s' % (a, t))
    count += 1

print('TOTAL_MATCHES=%d' % count)
