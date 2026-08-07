# MSVC500 FID Unmatched Functions and Audio Runtime Notes

This note captures the investigation after applying the generated MSVC500 FIDB
from `nafxcw.lib` and `libcmt.lib` to the Ghidra project.

## FIDB result

Dense candidate library range:

| Range | Total functions | FID matched | Unmatched |
|-------|----------------:|------------:|----------:|
| `0x005e539c..0x00626c7d` | 1650 | 1321 | 329 |

The 329 unmatched functions are not evidence of a single game-owned class region.
They are mostly functions that are naturally weak FID candidates: tiny thunks,
short duplicated wrappers, import jumps, CRT helper variants, compiler glue, and
MFC init/termination fragments.

## Unmatched shape

Size distribution for the 329:

| Size bucket | Count |
|-------------|------:|
| `<= 5` bytes | 98 |
| `6..8` bytes | 47 |
| `9..16` bytes | 52 |
| `17..32` bytes | 60 |
| `33..64` bytes | 33 |
| `>= 65` bytes | 39 |

Working classification:

| Bucket | Evidence |
|--------|----------|
| Tiny/thunk-like functions | 145 functions are `<= 8` bytes. |
| Small wrappers / dispatch stubs | Repeated `WrapperFor_*`, `thunk_*`, `AppendPointerToGlobalVector*` patterns. |
| CRT float / format / math helpers | `fpmath`, `ftol`, `setdefaultprecision`, FP-control and 96-bit integer helpers. |
| CRT heap / thread / runtime | TLS, critical-section, heap/free/realloc, stack probe, `amsg_exit`, CRT exit handlers. |
| MFC glue too short or variant-heavy for FID | Runtime-class pointer init, `CThreadLocalObject`, `CProcessLocalObject`, common-dialog message registration. |
| Import thunks | `GetOpenFileNameA`, `GetSaveFileNameA`, `OpenPrinterA`, commdlg registered-message helpers. |
| Manual triage remainder | Runtime-shaped islands that still need per-address confirmation before ownership changes. |

Representative clusters:

| Range | Shape |
|-------|-------|
| `0x005e5561..0x005e5661` | `CDragListBox`-style `Dropped` / listbox move helpers. |
| `0x005e7350..0x005e73d0` | CRT FP startup: `fpmath`, `ftol`, fpmath init table. |
| `0x005eada0..0x005eadfd` | CRT TLS / critical-section / heap reallocation helpers. |
| `0x005ec6c0..0x005ecc90` | CRT numeric string and float formatting helpers. |
| `0x005f3f90..0x005f4540` | FP-control and 96-bit integer helpers. |
| `0x005fa6f6..0x005fa714` | Import thunks for common dialog and printing APIs. |
| `0x005ffe27..0x005ffe9a` | Common-dialog registered-message wrappers. |
| `0x006076b8..0x006077c0` | MFC / CommCtrl drag-list and short init wrappers. |
| `0x006106e5..0x0061073e` | Mixed short MFC/runtime stubs, including the already-discussed `0x00610a57` neighborhood. |
| `0x00624487..0x006244ce` | MFC thread/process-local object init/dtor thunks. |

Conclusion for this range: keep the 329 in a library-residue triage queue. Do not
bulk-promote them as game code, but also do not blindly mark all 329 `// LIBRARY`
without checking the few longer manual-triage bodies.

## Audio runtime boundary

The sound/audio code adjacent to this area is not from `nafxcw.lib` or
`libcmt.lib`. It has three distinct layers:

| Code / data | Provenance |
|-------------|------------|
| `TSoundPlayer` methods at `0x005e4e70`, `0x005e4f80`, `0x005e50c0` | Game-owned audio subsystem. |
| `TSoundResourceManager` global at `0x006a60c0`, methods around `0x0049c240`, `0x0049c430`, `0x0049c850` | Game wave/resource manager. |
| Backend API calls | Windows multimedia APIs: `WINMM.dll`, `MSVFW32.dll`, `DSOUND.dll`. |

Important evidence:

| Address / source | Evidence |
|------------------|----------|
| `0x005e4e70` | `TSoundPlayer::InitializeSoundSubsystemAndAllocateChannelLists`; `thiscall`, initializes packet state, calls DirectSound init, allocates two channel nodes, not a static library body. |
| `0x005e4f80` | `TSoundPlayer::RequestDirectSoundInitIfAllowed`; checks `this+0x20`, sets `this+0x21`, then calls the DirectSound manager. |
| `0x005e50c0` | `TSoundPlayer::UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState`; rotates six sound slots and calls the wave manager at `0x006a60c0`. |
| `0x0049c970` | Initializes DirectSound state, calls `DSOUND.DLL::DirectSoundCreate`, sets cooperative level, initializes six channel entries. |
| `0x005e18f0` and nearby | CD-audio / mixer helpers using `mciSendCommandA`, `auxGetNumDevs`, `auxGetDevCapsA`, `auxGetVolume`. |
| `0x00707081` | Dynamically loads `wav-winmm.dll` and resolves `mciSendCommandA` / `aux*` symbols before continuing runtime init. |
| `tmp_decomp/w32dasm/imports.csv` | Direct imports include `WINMM.dll`, `MSVFW32.dll::MCIWndCreateA`, and `DSOUND.dll::DirectSoundCreate`. |

The installed GOG directory also contains a replacement `winmm.dll` and OGG/Vorbis
DLLs. That suggests the CD-audio wrapper aspect is distribution/runtime patching,
while the in-EXE `TSoundPlayer`, `TSoundResourceManager`, wave-slot rotation, and
DirectSound channel management remain game-side code.

Model the boundary as:

```text
audio area
|-- game source model
|   |-- TSoundPlayer virtual slots
|   |-- TSoundResourceManager / wave.gob loader
|   `-- channel objects / DirectSound buffer management
|-- Windows multimedia APIs
|   |-- WINMM.dll: mciSendCommandA, aux*
|   |-- MSVFW32.dll: MCIWndCreateA
|   `-- DSOUND.dll: DirectSoundCreate
`-- GOG/runtime shim evidence
    `-- wav-winmm.dll dynamic resolver / local winmm.dll + OGG/Vorbis files
```

Practical classification:

- Do not bulk-mark the sound manager/player code as `// LIBRARY`.
- Keep true imports and external API thunks library/runtime-owned.
- Continue recovering `TSoundResourceManager` methods as game code, especially
  `LoadWaveResourceByNumericIdAndBuildBuffer @ 0x0049c430` and
  `ReadWaveDataAndFormatViaLoaderWithRetry @ 0x0049c720`.
- Treat Win32/MMIO/MFC calls used by the wave loader as external library APIs, not
  as game-owned helpers.

## Evidence files and commands

Primary local evidence:

- `tmp_decomp/msvc500_library_range_audit.csv`
- `tmp_decomp/w32dasm/imports.csv`
- `config/thunk_map.csv`
- `config/symbols.csv`
- `src/game/TSoundPlayer.cpp`
- `include/game/TSoundResourceManager.h`
- `src/ghidra_autogen/global_part005.cpp`
- `src/ghidra_autogen/global_part011.cpp`
- `src/ghidra_autogen/global_part021.cpp`

Useful checks:

```sh
just ghidra listing 0x005e4e70 0x005e4f80 0x005e50c0 0x005e536e 0x005e5386
just ghidra decompile 0x005e18f0 0x00707081 0x0049c970 0x0049c430
rg -n "DirectSoundCreate|MCIWndCreateA|mciSendCommandA|auxGet" \
  config src include tmp_decomp/w32dasm/imports.csv
```
