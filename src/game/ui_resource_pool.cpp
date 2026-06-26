#include "game/mcappui_globals.h"

// FUNCTION: IMPERIALISM 0x0041b420
unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer) {
  buffer[0] = 0;
  buffer[1] = 0;
  buffer[2] = 0;
  buffer[3] = 0;
  buffer[4] = 0;
  buffer[5] = 0;
  buffer[6] = 0;
  buffer[7] = 0;
  return buffer;
}

// FUNCTION: IMPERIALISM 0x00479a80
void PopUiResourcePoolNode_00479A80(void) {}

// Minimal pool push/pop: turn-order navigation dialog init uses a single push/pop pair
// with no nested siblings; full freelist pool @ DAT_006a13e0 remains TODO.
// FUNCTION: IMPERIALISM 0x00479b00
void PushUiResourcePoolNode(void) {}
