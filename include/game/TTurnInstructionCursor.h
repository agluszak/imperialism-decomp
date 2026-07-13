#pragma once

// Shared read cursor for the TSimMgr turn-instruction stream handlers dispatched from
// TSimMgr::ProcessTurnInstructionStreamAndFinalizePhase (0x581e60). Each handler receives a
// pointer to an object whose first field is the current 4-byte-token read pointer; the
// dispatcher advances token by token. Every token carries its payload as a big-endian
// value in the high two bytes (bytes [2..3]) -- a legacy of the game's big-endian
// (68k/PowerPC CodeWarrior) on-disk instruction format read back on little-endian x86.
struct STurnInstructionCursor {
  unsigned int* tokenCursor;
};
