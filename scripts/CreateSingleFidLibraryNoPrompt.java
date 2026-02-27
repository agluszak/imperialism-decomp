// Headless-friendly script to populate one FID library from a project folder.
//
// Usage:
//   CreateSingleFidLibraryNoPrompt.java \
//     <fidbFilePath> \
//     <projectRootFolderPath> \
//     <libraryFamilyName> \
//     <libraryVersion> \
//     <libraryVariant> \
//     [languageID or "-"] \
//     [commonSymbolsFile or "-"]
//
//@category FunctionID

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class CreateSingleFidLibraryNoPrompt extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args == null || args.length < 5) {
			throw new IllegalArgumentException(
				"Expected at least 5 args: <fidbFilePath> <projectRootFolderPath> " +
					"<libraryFamilyName> <libraryVersion> <libraryVariant> " +
					"[languageID or -] [commonSymbolsFile or -]");
		}

		File fidbFile = new File(args[0]).getAbsoluteFile();
		String projectRootFolderPath = args[1];
		String familyName = args[2];
		String version = args[3];
		String variant = args[4];
		String languageArg = args.length >= 6 ? args[5] : "-";
		String commonSymbolsArg = args.length >= 7 ? args[6] : "-";

		DomainFolder root = ensureProjectFolder(projectRootFolderPath);
		ArrayList<DomainFile> programs = new ArrayList<>();
		findPrograms(programs, root);
		if (programs.isEmpty()) {
			throw new IOException("No programs found under folder: " + root.getPathname());
		}

		LanguageID languageID =
			("-".equals(languageArg) || languageArg.isEmpty()) ? inferLanguageId(programs.get(0))
					: new LanguageID(languageArg);
		List<String> commonSymbols = loadCommonSymbols(commonSymbolsArg);

		FidFileManager manager = FidFileManager.getInstance();
		if (!fidbFile.exists()) {
			File parent = fidbFile.getParentFile();
			if (parent != null && !parent.exists()) {
				parent.mkdirs();
			}
			manager.createNewFidDatabase(fidbFile);
			println("Created new fidb: " + fidbFile.getAbsolutePath());
		}
		FidFile fidFile = manager.addUserFidFile(fidbFile);
		if (fidFile == null) {
			throw new IOException("Failed to attach fidb: " + fidbFile.getAbsolutePath());
		}

		println("Populating fidb: " + fidbFile.getAbsolutePath());
		println("Source folder: " + root.getPathname());
		println("Program count: " + programs.size());
		println("Library: " + familyName + ":" + version + ":" + variant);
		println("LanguageID: " + languageID.getIdAsString());
		println("Common symbols loaded: " + (commonSymbols == null ? 0 : commonSymbols.size()));

		FidService service = new FidService();
		try (FidDB fidDb = fidFile.getFidDB(true)) {
			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb, familyName, version,
				variant, programs, null, languageID, null, commonSymbols, monitor);

			println("Populate result:");
			println("  totalAttempted=" + result.getTotalAttempted());
			println("  totalAdded=" + result.getTotalAdded());
			println("  totalExcluded=" + result.getTotalExcluded());
			println("  failures:");
			for (java.util.Map.Entry<FidPopulateResult.Disposition, Integer> entry : result.getFailures()
					.entrySet()) {
				if (entry.getValue() != null && entry.getValue().intValue() != 0) {
					println("    " + entry.getKey() + "=" + entry.getValue());
				}
			}

			fidDb.saveDatabase("CreateSingleFidLibraryNoPrompt", monitor);
			println("FID database saved.");
		}
	}

	private List<String> loadCommonSymbols(String pathArg) throws IOException {
		if (pathArg == null || pathArg.isEmpty() || "-".equals(pathArg)) {
			return null;
		}
		File file = new File(pathArg);
		List<String> symbols = new LinkedList<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line = reader.readLine();
			while (line != null) {
				if (!line.isEmpty()) {
					symbols.add(line);
				}
				line = reader.readLine();
			}
		}
		return symbols;
	}

	private LanguageID inferLanguageId(DomainFile file)
			throws VersionException, CancelledException, IOException {
		DomainObject domainObject = null;
		try {
			domainObject = file.getDomainObject(this, false, true, monitor);
			Program program = (Program) domainObject;
			return program.getLanguageID();
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}
	}

	private DomainFolder ensureProjectFolder(String path) throws IOException, InvalidNameException {
		DomainFolder root = state.getProject().getProjectData().getRootFolder();
		if ("/".equals(path) || "".equals(path)) {
			return root;
		}
		String p = path.startsWith("/") ? path.substring(1) : path;
		String[] parts = p.split("/");
		DomainFolder cur = root;
		for (String part : parts) {
			if (part.isEmpty()) {
				continue;
			}
			DomainFolder next = cur.getFolder(part);
			if (next == null) {
				next = cur.createFolder(mangleNameBecauseDomainFoldersAreSoRetro(part));
			}
			cur = next;
		}
		return cur;
	}

	private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder)
			throws CancelledException {
		if (folder == null) {
			return;
		}
		DomainFile[] files = folder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCancelled();
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			monitor.checkCancelled();
			findPrograms(programs, sub);
		}
	}

	private String mangleNameBecauseDomainFoldersAreSoRetro(String name) {
		if (name == null) {
			return "(NULL)";
		}
		if (name.equals("")) {
			return "(EMPTY)";
		}
		StringBuilder sb = new StringBuilder();
		char[] charArray = name.toCharArray();
		for (char c : charArray) {
			if (!LocalFileSystem.isValidNameCharacter(c)) {
				c = '_';
			}
			sb.append(c);
		}
		return sb.toString();
	}
}
