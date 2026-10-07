#include "decomp_types.h"

// Four unreferenced QuickDraw.cpp compatibility leaves; without callers, their names only
// describe code shape.

// FUNCTION: IMPERIALISM 0x0049dcc0
short QuickDrawCompatibilityStatus() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049dce0
void QuickDrawCompatibilityNoOp() {}

// FUNCTION: IMPERIALISM 0x0049dd00
int ReturnSecondArgument(int unused, int value) {
  return value;
}

// FUNCTION: IMPERIALISM 0x0049dd20
int QuickDrawCompatibilityReturnZero() {
  return 0;
}
