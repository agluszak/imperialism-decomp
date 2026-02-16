#@author codex
#@category Analysis

from collections import Counter, defaultdict

TARGETS = {
    0x004038fa: 'thunk_ConstructPictureResourceEntryType5EB60',
    0x004038ff: 'thunk_ConstructUiResourceEntryType60180',
    0x004087fb: 'thunk_ConstructUiResourceEntryType4A098',
}

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
refman = currentProgram.getReferenceManager()


def to_ascii4(v):
    b = [(v >> (8*i)) & 0xff for i in range(4)]
    s = ''.join(chr(x) if 32 <= x <= 126 else '.' for x in b)
    return s

for target, name in TARGETS.items():
    print('\n=== %s @ %08X ===' % (name, target))
    refs = list(refman.getReferencesTo(toAddr(target)))
    print('total_xrefs=%d' % len(refs))
    fn_counter = Counter()
    tag_counter = Counter()
    code_counter = Counter()

    for r in refs:
        from_addr = r.getFromAddress()
        fn = fm.getFunctionContaining(from_addr)
        fn_name = fn.getName() if fn else '<no_function>'
        fn_counter[fn_name] += 1

        ins = listing.getInstructionAt(from_addr)
        if ins is None:
            continue
        prev = ins.getPrevious()
        for _ in range(20):
            if prev is None:
                break
            txt = str(prev)
            low = txt.lower()
            if prev.getMnemonicString().upper() == 'PUSH' and '0x' in low:
                # parse immediate push
                try:
                    imm_txt = low.split('0x', 1)[1]
                    imm_hex = ''
                    for ch in imm_txt:
                        if ch in '0123456789abcdef':
                            imm_hex += ch
                        else:
                            break
                    if imm_hex:
                        v = int(imm_hex, 16)
                        if v <= 0xffff:
                            code_counter[v] += 1
                        if 0x20202020 <= v <= 0x7e7e7e7e:
                            tag_counter[to_ascii4(v)] += 1
                except Exception:
                    pass
            prev = prev.getPrevious()

    print('top_calling_functions:')
    for fn_name, cnt in fn_counter.most_common(15):
        print('  %4d  %s' % (cnt, fn_name))

    print('top_ascii4_pushes_near_calls:')
    for tag, cnt in tag_counter.most_common(20):
        print('  %4d  %s' % (cnt, tag))

    print('top_u16_pushes_near_calls:')
    for code, cnt in code_counter.most_common(20):
        print('  %4d  0x%X' % (cnt, code))
