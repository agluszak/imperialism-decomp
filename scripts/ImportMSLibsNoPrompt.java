// Headless-friendly variant of ImportMSLibs.java.
// Imports COFF members from MSVC .LIB archives into a chosen project folder.
// Usage:
//   ImportMSLibsNoPrompt.java [projectRootFolderPath] [scanDir1] [scanDir2] ...
// Defaults:
//   projectRootFolderPath = /msvc500_core/libs
//   scanDir1 = /home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/lib
//   scanDir2 = /home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/mfc-lib
//@category FunctionID

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;

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
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;

public class ImportMSLibsNoPrompt extends GhidraScript {

	private static final String DEFAULT_PROJECT_FOLDER = "/msvc500_core/libs";
	private static final String DEFAULT_SCAN_DIR_1 =
		"/home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/lib";
	private static final String DEFAULT_SCAN_DIR_2 =
		"/home/andrzej.gluszak/code/personal/imperialism_knowledge/fid/msvc500/mfc-lib";

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
		println("ImportMSLibsNoPrompt root folder: " + root.getPathname());
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

		println("ImportMSLibsNoPrompt done.");
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
		try (RandomAccessByteProvider provider = new RandomAccessByteProvider(file)) {
			if (!CoffArchiveHeader.isMatch(provider)) {
				return;
			}

			CoffArchiveHeader coffArchiveHeader = CoffArchiveHeader.read(provider, monitor);
			HashSet<Long> offsetsSeen = new HashSet<>();
			for (CoffArchiveMemberHeader archiveMemberHeader : coffArchiveHeader.getArchiveMemberHeaders()) {
				monitor.checkCancelled();
				if (offsetsSeen.contains(archiveMemberHeader.getPayloadOffset())) {
					continue;
				}
				offsetsSeen.add(archiveMemberHeader.getPayloadOffset());
				if (!archiveMemberHeader.isCOFF()) {
					continue;
				}
				String preferredName = archiveMemberHeader.getName();
				try (ByteProvider coffProvider = new ByteProviderWrapper(provider,
						archiveMemberHeader.getPayloadOffset(), archiveMemberHeader.getSize())) {
					CoffFileHeader header = new CoffFileHeader(coffProvider);
					if (!CoffMachineType.isMachineTypeDefined(header.getMagic())) {
						continue;
					}
					String[] splits = splitPreferredName(preferredName);
					try (LoadResults<Program> loadResults =
							ProgramLoader.builder()
								.source(coffProvider)
								.project(state.getProject())
								.projectFolderPath(root.getPathname())
								.loaders(MSCoffLoader.class)
								.compiler("windows")
								.name(mangleNameBecauseDomainFoldersAreSoRetro(splits[splits.length - 1]))
								.log(log)
								.monitor(new CancelOnlyWrappingTaskMonitor(monitor))
								.load()) {
						for (Loaded<Program> loaded : loadResults) {
							DomainObject d = loaded.getDomainObject(this);
							Program program = (Program) d;
							DomainFolder destination = null;
							try {
								loaded.save(monitor);
								destination = establishFolder(root, file, program, isDebug, splits);
								// NOTE:
								// Moving immediately after save can trigger FileInUseException in
								// headless mode for some archive members. Keep object in place and
								// rely on generated unique names/folders during import pass.
							}
							finally {
								program.release(this);
							}
							// Best-effort no-op to keep logic/side effects stable.
							if (destination != null) {
								/* intentionally not moving domain file */
							}
						}
					}
				}
				catch (LoadException e) {
					printerr("no programs loaded from " + file + " - " + preferredName);
				}
			}
		}
		catch (CoffException e) {
			printerr("COFF parse failed for " + file + ": " + e.getMessage());
		}
	}

	private DomainFolder establishFolder(DomainFolder root, File file, Program program, boolean isDebug,
			String[] splits) throws InvalidNameException, IOException {
		DomainFolder folder = root;
		LanguageDescription description = program.getLanguage().getLanguageDescription();
		String arch =
			description.getProcessor() + "-" + description.getSize() + "-" +
				description.getEndian().toShortString();
		folder = obtainSubfolder(folder, arch);

		String debuggishness = isDebug ? "debug" : "std";
		folder = obtainSubfolder(folder, debuggishness);

		ArrayList<File> path = new ArrayList<>();
		File current = file;
		path.add(current);
		while (current.getParentFile() != null) {
			path.add(current.getParentFile());
			current = current.getParentFile();
		}
		for (int ii = path.size() - 2; ii >= 0; --ii) {
			String entry = path.get(ii).getName();
			folder = obtainSubfolder(folder, entry);
		}

		for (int ii = 0; ii < splits.length - 1; ++ii) {
			String entry = splits[ii];
			if ("..".equals(entry)) {
				continue;
			}
			folder = obtainSubfolder(folder, entry);
		}
		return folder;
	}

	private DomainFolder obtainSubfolder(DomainFolder parent, String child)
			throws InvalidNameException, IOException {
		child = mangleNameBecauseDomainFoldersAreSoRetro(child);
		DomainFolder folder = parent.getFolder(child);
		if (folder == null) {
			folder = parent.createFolder(child);
		}
		return folder;
	}

	private String[] splitPreferredName(String preferredName) {
		return preferredName.split("[/\\\\]");
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
