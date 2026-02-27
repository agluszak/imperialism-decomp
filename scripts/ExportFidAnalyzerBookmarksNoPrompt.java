// Export Function ID Analyzer bookmarks for current program to CSV.
//
// Usage:
//   ExportFidAnalyzerBookmarksNoPrompt.java <outputCsvPath>
//
//@category FunctionID

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportFidAnalyzerBookmarksNoPrompt extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args == null || args.length < 1) {
			throw new IllegalArgumentException("Expected arg: <outputCsvPath>");
		}
		File outFile = new File(args[0]).getAbsoluteFile();
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists()) {
			parent.mkdirs();
		}

		BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
		FunctionManager functionManager = currentProgram.getFunctionManager();

		int totalAnalysis = 0;
		int fidRows = 0;

		try (FileWriter fw = new FileWriter(outFile)) {
			fw.write("address,function_name,bookmark_category,bookmark_comment\n");
			Iterator<Bookmark> it = bookmarkManager.getBookmarksIterator("Analysis");
			while (it.hasNext()) {
				monitor.checkCancelled();
				Bookmark bookmark = it.next();
				totalAnalysis += 1;
				String category = bookmark.getCategory();
				if (category == null || !category.contains("Function ID Analyzer")) {
					continue;
				}

				Function func = functionManager.getFunctionContaining(bookmark.getAddress());
				String functionName = func == null ? "" : func.getName();
				String comment = bookmark.getComment();
				if (comment == null) {
					comment = "";
				}
				fw.write(csv(bookmark.getAddress().toString()));
				fw.write(",");
				fw.write(csv(functionName));
				fw.write(",");
				fw.write(csv(category));
				fw.write(",");
				fw.write(csv(comment));
				fw.write("\n");
				fidRows += 1;
			}
		}
		catch (IOException e) {
			throw new IOException("Failed to write CSV: " + outFile, e);
		}

		println("Exported FID analyzer bookmarks:");
		println("  output=" + outFile.getAbsolutePath());
		println("  totalAnalysisBookmarks=" + totalAnalysis);
		println("  fidRows=" + fidRows);
	}

	private String csv(String s) {
		if (s == null) {
			return "\"\"";
		}
		String escaped = s.replace("\"", "\"\"");
		return "\"" + escaped + "\"";
	}
}
