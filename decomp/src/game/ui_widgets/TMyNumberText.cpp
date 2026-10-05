#include "game/ui_widgets/TMyNumberText.h"

#include "game/core/CString.h"
#include "game/mfc.h"

#include <stdlib.h>

// Defined below, in the original's address order.
void ParseIntFromControlText(CString text, int* outValue);

IMPLEMENT_DYNCREATE(TMyNumberText, TNumberText)

// FUNCTION: IMPERIALISM 0x005b4fd0
TMyNumberText::TMyNumberText() : TNumberText() {}

// No own destructor: the original's 0x005b5030 is an ILT thunk to the base's
// ~TEditText (0x004904d0), so this class inherits it. The scalar deleting destructor above is what
// the vtable slot holds.

// FUNCTION: IMPERIALISM 0x005b5050
int TMyNumberText::UpdateControlCachedIntFromWindowText() {
  int value = 0;
  CString text;
  GetCurrentText(&text);
  if (text.GetLength() != 0) {
    ParseIntFromControlText(text, &value);
  }
  return value;
}

// FUNCTION: IMPERIALISM 0x005b6a80
void ParseIntFromControlText(CString text, int* outValue) {
  *outValue = atoi(text);
}
