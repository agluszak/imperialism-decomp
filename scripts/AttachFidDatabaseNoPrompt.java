// Attach an existing FID database from script args (headless-friendly).
//
// Usage:
//   AttachFidDatabaseNoPrompt.java <fidbFilePath>
//
//@category FunctionID

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;

public class AttachFidDatabaseNoPrompt extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args == null || args.length < 1) {
			throw new IllegalArgumentException("Expected arg: <fidbFilePath>");
		}
		File dbFile = new File(args[0]).getAbsoluteFile();
		if (!dbFile.exists()) {
			throw new IllegalArgumentException("FID database does not exist: " + dbFile);
		}
		FidFile fidFile = FidFileManager.getInstance().addUserFidFile(dbFile);
		if (fidFile == null) {
			throw new IllegalStateException("Failed to attach fidb: " + dbFile);
		}
		println("Attached fidb: " + fidFile.getPath());
	}
}
