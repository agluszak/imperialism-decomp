#@author codex
#@category Analysis

TARGET_CALL = '0x00408715'
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CALL 0x00408715 sites with non-immediate PUSH arg ===')
count_all = 0
count_dyn = 0
for ins in listing.getInstructions(True):
    txt = str(ins).lower()
    if ins.getMnemonicString().upper() == 'CALL' and TARGET_CALL in txt:
        count_all += 1
        prev = ins.getPrevious()
        arg_ins = prev if prev and prev.getMnemonicString().upper() == 'PUSH' else None
        arg_txt = str(arg_ins) if arg_ins else '<no_direct_push>'
        is_dyn = True
        if arg_ins:
            low = arg_txt.lower()
            # immediate push heuristic
            if '0x' in low or any(ch.isdigit() for ch in low.split()[-1]):
                # treat register-only pushes as dynamic
                parts = low.replace(',', ' ').split()
                if len(parts) >= 2 and parts[-1].startswith('0x'):
                    is_dyn = False
                elif len(parts) >= 2 and parts[-1].isdigit():
                    is_dyn = False
        if is_dyn:
            addr = ins.getAddress()
            fn = fm.getFunctionContaining(addr)
            fn_name = fn.getName() if fn else '<no_function>'
            print('%s | %s | %s | arg=%s' % (addr, fn_name, ins, arg_txt))
            # show 6 lines before for provenance
            p = ins.getPrevious()
            lines = []
            for _ in range(6):
                if p is None:
                    break
                lines.append('%s: %s' % (p.getAddress(), p))
                p = p.getPrevious()
            lines.reverse()
            for line in lines:
                print('  ' + line)
            count_dyn += 1

print('TOTAL_CALLS=%d' % count_all)
print('DYNAMIC_ARG_SITES=%d' % count_dyn)
