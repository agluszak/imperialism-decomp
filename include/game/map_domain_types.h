#pragma once

// Strategic-map tile identity is stored and passed as a signed 16-bit value at the
// game-owned map boundary. The 108x60 map occupies 0..6479 and uses -1 as the common
// invalid/not-found sentinel. Representative listings 0x005125a0, 0x00512cc0, and
// 0x005136a0 load the argument as a word and sign-extend it before arithmetic/indexing.
typedef short StrategicTileIndex;

// Tactical battles use a separate 15x29 grid domain. Its indices, neighbor arrays,
// path buffers, and unit fields are all full dwords; 0x005a0420 reads and writes
// dwords throughout and 0x005a0550 compares a six-element dword neighbor array.
typedef int TacticalTileIndex;
