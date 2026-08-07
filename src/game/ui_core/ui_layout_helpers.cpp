#include "game/ui_core/ui_layout_helpers.h"

// FUNCTION: IMPERIALISM 0x005b7f80
bool __stdcall IsLayoutDispatchCodeAccepted(short code) {
  return (code >= 0 && code <= 6) || (code >= 0x11 && code <= 0x16);
}

// FUNCTION: IMPERIALISM 0x005c4c30
unsigned int CountLeadingSpansAtOrBeforePosition(const int* spans, int position) {
  unsigned int count = 0;
  for (int remaining = position - *spans; remaining >= 0; remaining -= *spans) {
    ++spans;
    ++count;
  }
  return count;
}
