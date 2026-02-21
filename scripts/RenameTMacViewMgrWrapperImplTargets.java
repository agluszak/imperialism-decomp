// Rename obvious TMacViewMgr wrapper implementation targets.
// Rule: wrapper named TMacViewMgr_On* calls exactly one generic FUN_* target,
// and that target is only called from this wrapper.
// Usage: postScript RenameTMacViewMgrWrapperImplTargets.java [apply]
// @category Imperialism/TMacViewMgr

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class RenameTMacViewMgrWrapperImplTargets extends GhidraScript {
	private static boolean isGenericName(String s) {
		return s.startsWith("FUN_") || s.startsWith("thunk_FUN_");
	}

	private static boolean isWrapperName(String s) {
		return s.startsWith("TMacViewMgr_On") && !s.endsWith("_Impl");
	}

	@Override
	protected void run() throws Exception {
		boolean apply = false;
		String[] args = getScriptArgs();
		if (args != null) {
			for (String a : args) {
				if ("apply".equalsIgnoreCase(a) || "true".equalsIgnoreCase(a)) {
					apply = true;
				}
			}
		}

		int candidates = 0;
		int renamed = 0;
		int skipped = 0;

		for (Function wrapper : currentProgram.getFunctionManager().getFunctions(true)) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			String wrapperName = wrapper.getName();
			if (!isWrapperName(wrapperName)) {
				continue;
			}

			Set<Function> genericCallees = new LinkedHashSet<>();
			Instruction ins = getInstructionAt(wrapper.getEntryPoint());
			Address max = wrapper.getBody().getMaxAddress();
			while (ins != null && ins.getAddress().compareTo(max) <= 0) {
				for (Reference ref : ins.getReferencesFrom()) {
					if (ref.getReferenceType().isCall()) {
						Function callee = getFunctionAt(ref.getToAddress());
						if (callee != null && isGenericName(callee.getName())) {
							genericCallees.add(callee);
						}
					}
				}
				ins = ins.getNext();
			}

			if (genericCallees.size() != 1) {
				continue;
			}

			Function callee = genericCallees.iterator().next();
			Reference[] refsTo = getReferencesTo(callee.getEntryPoint());
			Set<Address> callFromFuncs = new LinkedHashSet<>();
			for (Reference r : refsTo) {
				RefType rt = r.getReferenceType();
				if (!rt.isCall()) {
					continue;
				}
				Function f = getFunctionContaining(r.getFromAddress());
				if (f != null) {
					callFromFuncs.add(f.getEntryPoint());
				}
			}

			if (callFromFuncs.size() != 1 || !callFromFuncs.contains(wrapper.getEntryPoint())) {
				skipped++;
				continue;
			}

			String newName = wrapperName + "_Impl";
			if (newName.equals(callee.getName())) {
				continue;
			}

			candidates++;
			println(String.format(
				"CANDIDATE wrapper=%s @ %s -> callee=%s @ %s => %s",
				wrapperName,
				wrapper.getEntryPoint(),
				callee.getName(),
				callee.getEntryPoint(),
				newName));

			if (apply) {
				try {
					callee.setName(newName, SourceType.USER_DEFINED);
					renamed++;
					println("RENAMED " + callee.getEntryPoint() + " " + newName);
				}
				catch (Exception e) {
					skipped++;
					printerr("FAILED rename at " + callee.getEntryPoint() + ": " + e.getMessage());
				}
			}
		}

		println(String.format("SUMMARY apply=%s candidates=%d renamed=%d skipped=%d",
			Boolean.toString(apply), candidates, renamed, skipped));
	}
}
