// Headless-friendly MSVC .LIB importer with stable unique naming.
//
// Differences vs ImportMSLibsNoPrompt.java:
// - Uses unique program names: <LIBNAME>__<member_name>__<payload_offset_hex>
// - Skips obvious import-descriptor pseudo-members ending in ".DLL"
// - Emits compact per-library summary instead of one error line per failed member
//
// Usage:
//   ImportMSLibsNoPromptUnique.java [projectRootFolderPath] [scanDir1] [scanDir2] ...
//
//@category FunctionID

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.coff.CoffException;
import ghidra.app.util.bin.format.coff.CoffFileHeader;
import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.MSCoffLoader;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;

public class ImportMSLibsNoPromptUnique extends GhidraScript {

	private static final String DEFAULT_PROJECT_FOLDER = "/msvc500_unique/libs";
	private static final String DEFAULT_SCAN_DIR_1 =
		"/home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/lib";
	private static final String DEFAULT_SCAN_DIR_2 =
		"/home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/mfc-lib";

	private long importedPrograms = 0;
	private long skippedDllPseudoMembers = 0;
	private long skippedUnknownMachine = 0;
	private long skippedNonCoffMembers = 0;
	private long skippedDuplicatePayloadOffsets = 0;
	private long loadFailures = 0;
	private final Map<String, Integer> failuresByLibrary = new HashMap<>();
	private final Map<String, Integer> importedByLibrary = new HashMap<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String projectFolderPath = DEFAULT_PROJECT_FOLDER;
		ArrayList<File> scanDirs = new ArrayList<>();

		if (args != null && args.length > 0) {
			projectFolderPath = args[0];
			for (int i = 1; i < args.length; i++) {
				scanDirs.add(new File(args[i]));
			}
		}
		if (scanDirs.isEmpty()) {
			scanDirs.add(new File(DEFAULT_SCAN_DIR_1));
			scanDirs.add(new File(DEFAULT_SCAN_DIR_2));
		}

		DomainFolder root = ensureProjectFolder(projectFolderPath);
		println("ImportMSLibsNoPromptUnique root folder: " + root.getPathname());
		for (File f : scanDirs) {
			println("Scan dir: " + f.getAbsolutePath());
		}

		ArrayList<File> nonDebug = new ArrayList<>();
		ArrayList<File> debug = new ArrayList<>();
		findFiles(nonDebug, debug, scanDirs);
		MessageLog log = new MessageLog();

		println("Found non-debug .lib files: " + nonDebug.size());
		println("Found debug .lib files: " + debug.size());
		monitor.initialize(nonDebug.size() + debug.size());

		for (File file : nonDebug) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			importLibrary(root, file, false, log);
		}
		for (File file : debug) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			importLibrary(root, file, true, log);
		}

		println("ImportMSLibsNoPromptUnique summary:");
		println("  importedPrograms=" + importedPrograms);
		println("  loadFailures=" + loadFailures);
		println("  skippedDllPseudoMembers=" + skippedDllPseudoMembers);
		println("  skippedUnknownMachine=" + skippedUnknownMachine);
		println("  skippedNonCoffMembers=" + skippedNonCoffMembers);
		println("  skippedDuplicatePayloadOffsets=" + skippedDuplicatePayloadOffsets);

		TreeMap<String, Integer> importedSorted = new TreeMap<>(importedByLibrary);
		println("Imported per library:");
		for (Map.Entry<String, Integer> entry : importedSorted.entrySet()) {
			println("  " + entry.getKey() + ": " + entry.getValue());
		}

		TreeMap<String, Integer> failuresSorted = new TreeMap<>(failuresByLibrary);
		println("Load failures per library:");
		for (Map.Entry<String, Integer> entry : failuresSorted.entrySet()) {
			println("  " + entry.getKey() + ": " + entry.getValue());
		}

		println("ImportMSLibsNoPromptUnique done.");
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

	private void importLibrary(DomainFolder root, File file, boolean isDebug, MessageLog log)
			throws CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, IOException {
		String libName = file.getName();
		try (RandomAccessByteProvider provider = new RandomAccessByteProvider(file)) {
			if (!CoffArchiveHeader.isMatch(provider)) {
				return;
			}

			CoffArchiveHeader coffArchiveHeader = CoffArchiveHeader.read(provider, monitor);
			HashSet<Long> offsetsSeen = new HashSet<>();
			for (CoffArchiveMemberHeader archiveMemberHeader : coffArchiveHeader.getArchiveMemberHeaders()) {
				monitor.checkCancelled();
				long payloadOffset = archiveMemberHeader.getPayloadOffset();
				if (offsetsSeen.contains(payloadOffset)) {
					skippedDuplicatePayloadOffsets += 1;
					continue;
				}
				offsetsSeen.add(payloadOffset);
				if (!archiveMemberHeader.isCOFF()) {
					skippedNonCoffMembers += 1;
					continue;
				}

				String preferredName = archiveMemberHeader.getName();
				if (shouldSkipPseudoMember(preferredName)) {
					skippedDllPseudoMembers += 1;
					continue;
				}

				try (ByteProvider coffProvider =
					new ByteProviderWrapper(provider, payloadOffset, archiveMemberHeader.getSize())) {
					CoffFileHeader header = new CoffFileHeader(coffProvider);
					if (!CoffMachineType.isMachineTypeDefined(header.getMagic())) {
						skippedUnknownMachine += 1;
						continue;
					}

					String programName = buildProgramName(file, preferredName, payloadOffset, isDebug);
					try (LoadResults<Program> loadResults =
						ProgramLoader.builder()
							.source(coffProvider)
							.project(state.getProject())
							.projectFolderPath(root.getPathname())
							.loaders(MSCoffLoader.class)
							.compiler("windows")
							.name(programName)
							.log(log)
							.monitor(new CancelOnlyWrappingTaskMonitor(monitor))
							.load()) {
						for (Loaded<Program> loaded : loadResults) {
							DomainObject d = loaded.getDomainObject(this);
							Program program = (Program) d;
							try {
								loaded.save(monitor);
								importedPrograms += 1;
								increment(importedByLibrary, libName);
							}
							finally {
								program.release(this);
							}
						}
					}
				}
				catch (LoadException e) {
					loadFailures += 1;
					increment(failuresByLibrary, libName);
				}
			}
		}
		catch (CoffException e) {
			printerr("COFF parse failed for " + file + ": " + e.getMessage());
		}
	}

	private boolean shouldSkipPseudoMember(String preferredName) {
		if (preferredName == null) {
			return true;
		}
		String upper = preferredName.toUpperCase();
		return upper.endsWith(".DLL") || upper.endsWith(".DLL/");
	}

	private String buildProgramName(File libFile, String preferredName, long payloadOffset, boolean isDebug) {
		String libBase = libFile.getName();
		int dot = libBase.lastIndexOf('.');
		if (dot > 0) {
			libBase = libBase.substring(0, dot);
		}

		String memberName = preferredName;
		int slash = Math.max(memberName.lastIndexOf('/'), memberName.lastIndexOf('\\'));
		if (slash >= 0 && slash + 1 < memberName.length()) {
			memberName = memberName.substring(slash + 1);
		}
		memberName = mangleNameBecauseDomainFoldersAreSoRetro(memberName);
		libBase = mangleNameBecauseDomainFoldersAreSoRetro(libBase);
		String dbg = isDebug ? "D" : "R";
		return libBase + "__" + memberName + "__" + dbg + "__" + Long.toHexString(payloadOffset);
	}

	private void increment(Map<String, Integer> map, String key) {
		Integer old = map.get(key);
		map.put(key, old == null ? 1 : old + 1);
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

	private void findFiles(ArrayList<File> nonDebug, ArrayList<File> debug, ArrayList<File> directories)
			throws CancelledException {
		for (File directory : directories) {
			monitor.checkCancelled();
			findFiles(nonDebug, debug, directory);
		}
	}

	private void findFiles(ArrayList<File> nonDebug, ArrayList<File> debug, File directory)
			throws CancelledException {
		ArrayList<File> subdirs = new ArrayList<>();
		ArrayList<File> myNonDebug = new ArrayList<>();
		ArrayList<File> myDebug = new ArrayList<>();
		File[] files = directory.listFiles();
		if (files != null) {
			for (File file : files) {
				monitor.checkCancelled();
				if (file.isFile()) {
					String lowerName = file.getName().toLowerCase();
					if (lowerName.endsWith(".lib")) {
						if (lowerName.endsWith("d.lib")) {
							myDebug.add(file);
						}
						else {
							myNonDebug.add(file);
						}
					}
				}
				else if (file.isDirectory()) {
					subdirs.add(file);
				}
			}
		}
		nonDebug.addAll(myNonDebug);
		debug.addAll(myDebug);
		for (File sub : subdirs) {
			monitor.checkCancelled();
			findFiles(nonDebug, debug, sub);
		}
	}
}
