#@author codex
#@category Analysis

import re
from collections import defaultdict

TARGET_GLOBALS = {
    0x006a1420: 'g_pUiResourceContext',
    0x006a20f8: 'g_pLocalizationTable',
    0x006a43d4: 'g_pGlobalMapState',
    0x006a21bc: 'g_pUiRuntimeContext',
    0x006a2148: 'g_pUiViewManager',
}

re_call_mem = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x([0-9a-f]+)\]\s*$', re.IGNORECASE)

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

summary = {g: defaultdict(int) for g in TARGET_GLOBALS}
examples = {g: {} for g in TARGET_GLOBALS}

for ins in listing.getInstructions(True):
    txt = str(ins)
    m = re_call_mem.match(txt)
    if not m:
        continue

    reg = m.group(1).lower()
    off = int(m.group(2), 16)

    prev = ins.getPrevious()
    matched_global = None
    depth = 0
    while prev is not None and depth < 24:
        ptxt = str(prev).lower().replace(' ', '')
        for g in TARGET_GLOBALS:
            marker = 'mov%s,dwordptr[0x%08x]' % (reg, g)
            if marker in ptxt:
                matched_global = g
                break
        if matched_global is not None:
            break
        prev = prev.getPrevious()
        depth += 1

    if matched_global is None:
        continue

    summary[matched_global][off] += 1
    if off not in examples[matched_global]:
        fn = fm.getFunctionContaining(ins.getAddress())
        fn_name = fn.getName() if fn else '<no_function>'
        examples[matched_global][off] = '%s @ %s' % (fn_name, ins.getAddress())

print('=== vtable offset summary by global object pointer ===')
for g in TARGET_GLOBALS:
    name = TARGET_GLOBALS[g]
    hits = summary[g]
    total = sum(hits.values())
    print('\n%s (0x%08x) total_calls=%d unique_offsets=%d' % (name, g, total, len(hits)))
    if not hits:
        continue
    ordered = sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))
    for off, cnt in ordered[:20]:
        ex = examples[g].get(off, '')
        print('  +0x%02x count=%d example=%s' % (off, cnt, ex))
