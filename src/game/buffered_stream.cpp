// Static CRT stdio stream helpers (MSVC 5.0) -- LIBRARY markers for reccmp only.
// MFC CStdioFile wraps a CRT FILE*; these bodies are the runtime FILE/_iobuf layer,
// not game source.

// LIBRARY: IMPERIALISM 0x005d4ba0
// fgets-style line read from CRT FILE

// LIBRARY: IMPERIALISM 0x005e8760
// atoi-style signed decimal parse

// LIBRARY: IMPERIALISM 0x005e8800
// atoi wrapper

// LIBRARY: IMPERIALISM 0x005e9010
// fclose-style stream close

// LIBRARY: IMPERIALISM 0x005e9050
// flush/close/reset CRT FILE state

// LIBRARY: IMPERIALISM 0x005e90c0
// fopen-style stream open with mode

// LIBRARY: IMPERIALISM 0x005e9100
// fopen wrapper

// LIBRARY: IMPERIALISM 0x005e9440
// fread wrapper with stream lock

// LIBRARY: IMPERIALISM 0x005e9480
// fread core over CRT FILE buffer

// LIBRARY: IMPERIALISM 0x005e95c0
// getc-style read with stream lock

// LIBRARY: IMPERIALISM 0x005edbc0
// CRT FILE stream lock enter

// LIBRARY: IMPERIALISM 0x005edc30
// CRT FILE stream lock leave

// LIBRARY: IMPERIALISM 0x005efd50
// close low-level file descriptor

// LIBRARY: IMPERIALISM 0x005efe50
// free CRT FILE buffer

// LIBRARY: IMPERIALISM 0x005eff10
// fflush pending write buffer

// LIBRARY: IMPERIALISM 0x005f0050
// initialize CRT FILE from mode string

// LIBRARY: IMPERIALISM 0x005f0220
// allocate/reuse CRT FILE slot

// LIBRARY: IMPERIALISM 0x005f1490
// refill CRT FILE buffer and read first byte

// LIBRARY: IMPERIALISM 0x005f1580
// read low-level file descriptor
