#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGETS = [
    (toAddr(0x0047f8b0), 'AppendRuntimeSelectionRecordEntry'),
    (toAddr(0x00480500), 'ShowRuntimeSelectionDialogAndReturnRecord'),
]

for target, name in TARGETS:
    print('=== CALLS TO %s %s ===' % (name, target))
    refs = getReferencesTo(target)
    count = 0
    for ref in refs:
        if ref.getReferenceType() not in (RefType.UNCONDITIONAL_CALL, RefType.CONDITIONAL_CALL):
            continue
        src = ref.getFromAddress()
        ins = listing.getInstructionAt(src)
        fn = fm.getFunctionContaining(src)
        fn_name = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fn_name, ins))

        # print up to 12 previous instructions for argument provenance
        prev = ins.getPrevious() if ins else None
        window = []
        for _ in range(12):
            if prev is None:
                break
            window.append(prev)
            prev = prev.getPrevious()
        for p in reversed(window):
            print('  %s: %s' % (p.getAddress(), p))
        count += 1
    print('TOTAL_CALLS=%d' % count)
    print('')
