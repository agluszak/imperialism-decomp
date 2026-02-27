# MSVC 5.0 FID Setup (Imperialism Workspace)

## What is prepared

- Raw MSVC 5.0 corpus extracted from `imperialism-msvc500` image:
  - `fid/msvc500/lib`
  - `fid/msvc500/mfc-lib`
  - `fid/msvc500/redist`
  - `fid/msvc500/debug`
- Smaller practical subset:
  - `fid/msvc500_core`
- Note: legacy Java helper scripts under `scripts/` were removed during tooling cleanup.
  Use direct Ghidra GUI/headless workflows instead of repo-local Java script automation.
- Seed project with imported MSVC5 COFF members:
  - `msvc500-fid-import-v4`

## Create the FID database in Ghidra (GUI)

1. Open project `msvc500-fid-import-v4`.
2. Create DB: `Tools -> Function ID -> Create new empty FidDb...`
   - Suggested filename: `msvc500_x86_custom.fidb`
3. Populate DB: `Tools -> Function ID -> Populate FidDb from programs...`
   - Select the new `msvc500_x86_custom.fidb`.
   - Choose source folder: `/msvc500_core/libs` (inside that project).
   - Language ID: `x86:LE:32:default`
   - Common symbols file:
     `/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC/Ghidra/Features/FunctionID/data/common_symbols_win32.txt`
4. (Optional) Repack DB with `RepackFid.java`.
5. Attach DB to the Imperialism project:
   - `Tools -> Function ID -> Attach existing FidDb...`
6. Re-run analysis with `Function ID` enabled on `Imperialism.exe`.

## Notes

- COFF import emits relocation warnings for some archive members; this is expected for many static-lib members and does not block FID population.
- This is MSVC 5.0-era corpus from your own toolchain image, so it is materially closer than generic `vsOlder_x86.fidbf`.
