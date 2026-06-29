#include "game/map_action_context_helpers.h"

// FUNCTION: IMPERIALISM 0x0055f0b0
short __fastcall GetShortAtOffset14OrInvalid(void* objectPtr) {
  if (objectPtr == 0) {
    return -1;
  }
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(objectPtr) + 0x14);
}
