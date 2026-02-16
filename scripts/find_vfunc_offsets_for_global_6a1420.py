#@author codex
#@category Analysis

import re
from collections import defaultdict

TARGET = toAddr(0x006a1420)  # g_pUiResourceContext
MAX_FUNCS = 140
re_call_mem = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x([0-9a-f]+)\]\s*$', re.IGNORECASE)

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

refs = getReferencesTo(TARGET)
funcs = {}
for r in refs:
    fn = fm.getFunctionContaining(r.getFromAddress())
    if fn is not None:
        funcs[fn.getEntryPoint().toString()] = fn

func_list = sorted(funcs.values(), key=lambda f: f.getEntryPoint())[:MAX_FUNCS]
print('target=%s refs=%d funcs=%d sampled=%d' % (TARGET, len(refs), len(funcs), len(func_list)))

all_counts = defaultdict(int)
strong_counts = defaultdict(int)
examples = {}

for fn in func_list:
    it = listing.getInstructions(fn.getBody(), True)
    window = []
    for ins in it:
        txt = str(ins)
        m = re_call_mem.match(txt)
        if m:
            off = int(m.group(2), 16)
            reg = m.group(1).lower()
            all_counts[off] += 1
            if off not in examples:
                examples[off] = '%s @ %s' % (fn.getName(), ins.getAddress())

            strong = False
            for p in window[-12:]:
                ptxt = str(p).lower().replace(' ', '')
                if ('mov%s,dwordptr[0x006a1420]' % reg) in ptxt:
                    strong = True
                    break
            if strong:
                strong_counts[off] += 1

        window.append(ins)
        if len(window) > 16:
            window.pop(0)

print('=== offsets (sampled functions) ===')
for off, cnt in sorted(all_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:30]:
    print('  +0x%02x all=%d strong=%d example=%s' % (off, cnt, strong_counts.get(off, 0), examples.get(off, '')))
