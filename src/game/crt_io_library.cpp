// Static CRT helpers (MSVC 5.0) — LIBRARY markers for reccmp pairing only.
// Covers CRT I/O, time, and static-init/onexit machinery. Game code reaches these
// through the real CRT API (<io.h> _findfirst/_findnext/_findclose, <new.h>
// _set_new_handler) or they are CRT init-table entries / onexit callbacks seeded by the
// C runtime startup; do not hand-port them.

// LIBRARY: IMPERIALISM 0x005e7ae0
// _findfirst (FindFirstFileAndPopulateFileInfoRecord)

// LIBRARY: IMPERIALISM 0x005e7c10
// _findnext (FindNextFileAndPopulateFileInfoRecord)

// LIBRARY: IMPERIALISM 0x005e7d30
// _findclose

// LIBRARY: IMPERIALISM 0x005e7a80
// _set_new_handler — swaps the CRT new-handler pointer at 0x6a7fac (read by __callnewh
// 0x5e7ac0) under CRT lock #9; installed handler is ShowOutOfMemoryErrorNewHandler
// (0x412d90) from ImperialismApp::InitInstance

// LIBRARY: IMPERIALISM 0x005e7d60
// ConvertFileTimeToLocalEpochSeconds

// LIBRARY: IMPERIALISM 0x005eada0
// WrapperFor_GetOrCreateCrtThreadDataFromTls_At005eada0

// LIBRARY: IMPERIALISM 0x005edcc0
// ConvertBrokenDownLocalTimeToEpochSeconds

// LIBRARY: IMPERIALISM 0x005ef5d0
// EnsureRuntimeLocaleTablesInitializedOnce

// LIBRARY: IMPERIALISM 0x005ef910
// isindst

// CRT static-init entries (0x4943e0 / 0x494460) for the QuickDraw cached-font clusters.
// Each seeds its cluster's preset globals (g_QuickDrawMeasureFontPreset at 0x6a1d4c /
// g_QuickDrawCachedFontPreset at 0x6a1cec) to {0xc,0xc,0xc,0xc} + dirty=1 and registers
// the matching onexit release callback (0x494430 / 0x4944b0) via
// AppendPointerToGlobalVectorAsStatus (0x5e7920, the CRT onexit registration). These are
// _initterm-table entries run by the C runtime startup, not game logic; the globals stay
// zero-initialized in the .data image (seeded at runtime) and the font engines rebuild
// on first use via their null-cache fallback.

// LIBRARY: IMPERIALISM 0x004943e0
// WrapperFor_AppendPointerToGlobalVectorAsStatus_At004943e0

// LIBRARY: IMPERIALISM 0x00494430
// ReleaseQuickDrawCachedFontHandleIfPresent_At00494430

// LIBRARY: IMPERIALISM 0x00494460
// WrapperFor_AppendPointerToGlobalVectorAsStatus_At00494460

// LIBRARY: IMPERIALISM 0x004944b0
// ReleaseCachedGlobalFontObjectIfPresent_At004944b0
