#pragma once

// Shared inline helpers for byte-swapping serialized nation data.
// Used by TGreatPower and TAutoGreatPower.

#include "game/global_data_tables.h"
#include "game/map_action_context_helpers.h"

static __inline void SwapShortArrayBytes(void* base, int count) {
  unsigned char* bytes = reinterpret_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = t;
    bytes += 2;
    ++i;
  }
}

static __inline short GetShortAtOffset14OrInvalidValue(void) {
  return GetShortAtOffset14OrInvalid(g_pMapActionContextListHead);
}
