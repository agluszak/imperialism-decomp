// Counts function naming progress in the current program.
// @category Imperialism/Stats

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;

public class CountRenamedFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int total = 0;
		int userDefined = 0;
		int nonGeneric = 0;

		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			total++;
			Symbol sym = fn.getSymbol();
			if (sym != null && sym.getSource() == SourceType.USER_DEFINED) {
				userDefined++;
			}

			String name = fn.getName();
			if (!name.startsWith("FUN_") && !name.startsWith("thunk_FUN_")) {
				nonGeneric++;
			}
		}

		println("PROGRAM=" + currentProgram.getName());
		println("TOTAL_FUNCTIONS=" + total);
		println("USER_DEFINED_FUNCTION_SYMBOLS=" + userDefined);
		println("NON_GENERIC_NAMES=" + nonGeneric);
	}
}
