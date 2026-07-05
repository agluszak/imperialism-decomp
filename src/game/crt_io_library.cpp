// Static CRT I/O and time helpers (MSVC 5.0) — LIBRARY markers for reccmp pairing only.
// Game code reaches these through the real CRT API (<io.h> _findfirst/_findnext/_findclose,
// <new.h> _set_new_handler); do not hand-port them.

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
