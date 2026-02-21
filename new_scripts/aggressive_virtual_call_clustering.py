import re

max_funcs = 200
args = getScriptArgs()
if len(args) > 0:
    try:
        max_funcs = int(args[0])
    except Exception:
        pass

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

off_rx = re.compile(r"CALL\\s+dword ptr \\[[A-Z]{2,3}\\s*\\+\\s*0x([0-9a-fA-F]+)\\]")
plain_rx = re.compile(r"CALL\\s+dword ptr \\[[A-Z]{2,3}\\]")

func_scores = []
off_count = {}

it = fm.getFunctions(True)
while it.hasNext():
    f = it.next()
    offs = []
    ins_it = listing.getInstructions(f.getBody(), True)
    while ins_it.hasNext():
        ins = ins_it.next()
        if ins.getMnemonicString().upper() != "CALL":
            continue
        t = str(ins)
        m = off_rx.match(t)
        if m:
            off = int(m.group(1), 16)
            offs.append(off)
            off_count[off] = off_count.get(off, 0) + 1
            continue
        if plain_rx.match(t):
            offs.append(0)
            off_count[0] = off_count.get(0, 0) + 1
    if len(offs) >= 2:
        uniq = sorted(set(offs))
        func_scores.append((f.getEntryPoint(), f.getName(), len(offs), uniq))

func_scores.sort(key=lambda x: x[2], reverse=True)
print("=== TOP_FUNCTIONS ===")
for ep, nm, cnt, uniq in func_scores[:max_funcs]:
    offs_txt = ",".join(["0x%x" % x for x in uniq[:16]])
    print("0x%s | %s | vcall_count=%d | offsets=%s" % (ep, nm, cnt, offs_txt))

print("=== TOP_OFFSETS ===")
for off, cnt in sorted(off_count.items(), key=lambda kv: kv[1], reverse=True)[:80]:
    print("0x%x | count=%d" % (off, cnt))
