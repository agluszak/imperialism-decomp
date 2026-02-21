args = getScriptArgs()
if len(args) < 1:
    print("usage: <func_addr>")
else:
    f = getFunctionContaining(toAddr(args[0]))
    if f is None:
        print("NO_FUNCTION")
    else:
        print("FUNCTION %s @ %s" % (f.getName(), f.getEntryPoint()))
        ins = currentProgram.getListing().getInstructions(f.getBody(), True)
        for i in ins:
            if i.getMnemonicString().upper() != "CALL":
                continue
            t = i.toString()
            if "[" not in t:
                continue
            if "+ 0x" in t or "-" in t:
                print("%s | %s" % (i.getAddress(), t))
