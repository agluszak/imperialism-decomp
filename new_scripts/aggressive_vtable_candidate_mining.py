min_run = 4
max_rows = 200
args = getScriptArgs()
if len(args) > 0:
    try:
        min_run = int(args[0])
    except Exception:
        pass
if len(args) > 1:
    try:
        max_rows = int(args[1])
    except Exception:
        pass

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

def is_exec_ptr(v):
    try:
        a = toAddr(v)
    except Exception:
        return None
    b = mem.getBlock(a)
    if b is None or (not b.isExecute()):
        return None
    f = fm.getFunctionContaining(a)
    return f

rows = []
for block in mem.getBlocks():
    if not block.isInitialized() or block.isExecute():
        continue
    a = block.getStart()
    end = block.getEnd()
    # dword aligned walking
    run_start = None
    run_funcs = []
    while a <= end.subtract(3):
        try:
            v = getInt(a) & 0xFFFFFFFF
        except Exception:
            v = None
        f = is_exec_ptr(v) if v is not None else None
        if f is not None:
            if run_start is None:
                run_start = a
                run_funcs = []
            run_funcs.append(f)
        else:
            if run_start is not None:
                run_len = len(run_funcs)
                if run_len >= min_run:
                    names = []
                    seen = set()
                    for fn in run_funcs[:6]:
                        nm = "%s@%s" % (fn.getName(), fn.getEntryPoint())
                        if nm in seen:
                            continue
                        seen.add(nm)
                        names.append(nm)
                    rows.append((run_start, run_len, block.getName(), names))
                run_start = None
                run_funcs = []
        a = a.add(4)
    if run_start is not None:
        run_len = len(run_funcs)
        if run_len >= min_run:
            names = []
            seen = set()
            for fn in run_funcs[:6]:
                nm = "%s@%s" % (fn.getName(), fn.getEntryPoint())
                if nm in seen:
                    continue
                seen.add(nm)
                names.append(nm)
            rows.append((run_start, run_len, block.getName(), names))

rows.sort(key=lambda x: x[1], reverse=True)
for start, ln, blk, names in rows[:max_rows]:
    print("0x%s | run=%d | block=%s | funcs=%s" % (start, ln, blk, ";".join(names)))
