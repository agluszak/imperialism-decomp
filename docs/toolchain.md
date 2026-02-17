# Toolchain Notes

This document tracks evidence for the compiler/linker used by Imperialism (1997), and the current reproduction strategy.

## Current Hypothesis

- Architecture: 32-bit x86 PE
- Compiler family: Microsoft Visual C++ (late 90s)
- Most likely candidate range: VC++ 4.x to VC++ 6.0

## Initial Binary Fingerprints (GOG Imperialism.exe)

From `objdump -p` and `strings` on:
`/home/andrzej.gluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Imperialism.exe`

- PE timestamp: `Fri Oct 31 01:07:39 1997`
- PE linker version: `5.0`
- Subsystem: `Windows GUI`, subsystem version `4.0`
- No import of `MSVCRT.dll` (suggests statically linked CRT runtime)
- String present: `Microsoft Visual C++ Runtime Library`
- Extra section present: `.patch` (likely distributor patching layer)
- Rich header: not present in DOS stub (`e_lfanew = 0x80`, no `Rich`/`DanS` marker before PE header)

Re-check command:

```bash
uv run python tools/forensics/check_rich_header.py /home/andrzej.gluszak/Games/gog/imperialism/drive_c/GOG\ Games/Imperialism/Imperialism.exe
```

Observed output:

- `e_lfanew: 0x80`
- `rich_in_dos_region: False`
- `dans_in_dos_region: False`
- `rich_offsets_before_pe_header: []`

Interpretation:

- Missing Rich header means VC++ 4.2 is not ruled out by that signal.
- Linker `5.0` is still a meaningful clue for VC++ 5-era tooling, but should not be treated as final proof yet.
- VC++ 6.0 usually reports linker major version `6`, so it remains less likely.
- Because this is a GOG-distributed executable with an extra `.patch` section, keep post-build modifications in scope.

## Suggested Toolchain Order

1. VC++ 5.0-era compiler/linker and VC++ 4.2-era compiler/linker (parallel early experiments)
2. VC++ 6.0-era (only if matching evidence contradicts early fingerprints)

## Evidence To Collect

- Import table and CRT fingerprints (`MSVCRT`, `MSVCRxx`, startup symbols)
- Function prolog/epilog patterns
- Exception handling layout (`__CxxFrameHandler`, SEH style)
- RTTI/vtable layout details
- String and section ordering behavior from linker output

## Practical Strategy

1. Start with a modern-hosted old-compiler setup that can build 32-bit PE binaries.
2. Reconstruct a small set of functions and compare with `reccmp`.
3. Iterate compiler flags before broad source reconstruction.
4. Record every attempted compiler/version/flags set and observed matching deltas.

## Experiment Log Template

- Date:
- Compiler:
- Linker:
- Flags:
- Target function set:
- Match result:
- Notable mismatches:
- Next change:
