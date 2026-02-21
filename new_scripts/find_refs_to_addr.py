args = getScriptArgs()
if len(args) < 1:
    print("usage: <address_hex> [max_refs]")
else:
    target = toAddr(args[0])
    max_refs = 100
    if len(args) > 1:
        try:
            max_refs = int(args[1])
        except Exception:
            pass
    print("TARGET %s" % target)
    refs = getReferencesTo(target)
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    count = 0
    seen = set()
    for r in refs:
        from_addr = r.getFromAddress()
        fn = fm.getFunctionContaining(from_addr)
        fn_name = "<no_func>" if fn is None else fn.getName()
        key = "%s|%s" % (from_addr, fn_name)
        if key in seen:
            continue
        seen.add(key)
        ins = listing.getInstructionAt(from_addr)
        ins_text = "<no_inst>" if ins is None else str(ins)
        print("%s | %s | %s" % (from_addr, fn_name, ins_text))
        count += 1
        if count >= max_refs:
            break
    print("TOTAL_SHOWN %d" % count)
