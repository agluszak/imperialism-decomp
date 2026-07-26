#include "decomp_types.h"

// Four unreferenced QuickDraw.cpp compatibility leaves survive immediately before the
// application-command classes. Their ABIs are only as strong as the raw instructions:
// none has a code/data caller, so the names intentionally describe code shape rather than
// assigning an unsupported Mac Toolbox identity.

// FUNCTION: IMPERIALISM 0x0049dcc0
short QuickDrawCompatibilityReturnZeroShort_0049DCC0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049dce0
void QuickDrawCompatibilityNoOp_0049DCE0() {}

// FUNCTION: IMPERIALISM 0x0049dd00
int QuickDrawCompatibilityReturnSecondArgument_0049DD00(int unused, int value) {
  (void)unused;
  return value;
}

// FUNCTION: IMPERIALISM 0x0049dd20
int QuickDrawCompatibilityReturnZero_0049DD20() {
  return 0;
}
