import re

terms = [
    "window", "wnd", "dialog", "frame", "view", "toolbar", "tooltip", "class", "mainframe"
]
rx = re.compile("|".join([re.escape(t) for t in terms]), re.IGNORECASE)

min_len = 6
max_hits = 300
args = getScriptArgs()
if len(args) > 0:
    try:
        min_len = int(args[0])
    except Exception:
        pass
if len(args) > 1:
    try:
        max_hits = int(args[1])
    except Exception:
        pass

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

def u8(addr):
    return mem.getByte(addr) & 0xFF

hits = []
for block in mem.getBlocks():
    if not block.isInitialized():
        continue
    a = block.getStart()
    end = block.getEnd()
    cur = []
    cur_start = None
    while a <= end:
        b = u8(a)
        is_print = 0x20 <= b <= 0x7E
        if is_print:
            if cur_start is None:
                cur_start = a
            cur.append(chr(b))
        else:
            if cur_start is not None and len(cur) >= min_len:
                s = "".join(cur)
                if rx.search(s):
                    refs = getReferencesTo(cur_start)
                    callers = []
                    seen = set()
                    for r in refs:
                        f = fm.getFunctionContaining(r.getFromAddress())
                        if f is None:
                            continue
                        key = "%s@%s" % (f.getName(), f.getEntryPoint())
                        if key in seen:
                            continue
                        seen.add(key)
                        callers.append(key)
                        if len(callers) >= 4:
                            break
                    hits.append((cur_start, s, len(refs), callers))
            cur_start = None
            cur = []
        a = a.add(1)

hits.sort(key=lambda x: (x[2], len(x[1])), reverse=True)
for addr, s, rc, callers in hits[:max_hits]:
    print("0x%s | %s | refs=%d | callers=%s" % (addr, s, rc, ";".join(callers)))
