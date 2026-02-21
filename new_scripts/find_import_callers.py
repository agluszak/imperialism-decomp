from ghidra.app.script import GhidraScript


class FindImportCallers(GhidraScript):
    def run(self):
        args = self.getScriptArgs()
        if len(args) == 0:
            self.println("usage: <import_name> [max_refs]")
            return

        import_name = args[0]
        max_refs = 50
        if len(args) > 1:
            try:
                max_refs = int(args[1])
            except Exception:
                pass

        st = self.currentProgram.getSymbolTable()
        syms = st.getSymbols(import_name)
        target = None
        for s in syms:
            target = s
            break

        if target is None:
            self.println("NOT_FOUND: " + import_name)
            return

        addr = target.getAddress()
        self.println("TARGET: %s @ %s" % (import_name, addr))

        refs = self.getReferencesTo(addr)
        fm = self.currentProgram.getFunctionManager()
        listing = self.currentProgram.getListing()

        count = 0
        for r in refs:
            from_addr = r.getFromAddress()
            fn = fm.getFunctionContaining(from_addr)
            inst = listing.getInstructionAt(from_addr)
            fn_name = "<no_func>" if fn is None else fn.getName()
            inst_text = "<no_inst>" if inst is None else str(inst)
            self.println("%s | %s | %s" % (from_addr, fn_name, inst_text))
            count += 1
            if count >= max_refs:
                break

        self.println("TOTAL_SHOWN: %d" % count)
