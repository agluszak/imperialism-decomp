#include "game/TMyNumberText.h"

#include "game/CString.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x005b4f10
// TMyNumberText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b4fb0
// TMyNumberText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMyNumberText, TNumberText)

// In the binary the trivial TNumberText ctor body (value = 0) is inlined here after the
// TEditText base ctor call; the out-of-line TNumberText::TNumberText call this emits is
// an accepted codegen difference.
// FUNCTION: IMPERIALISM 0x005b4fd0
TMyNumberText::TMyNumberText() : TNumberText() {}

// SYNTHETIC: IMPERIALISM 0x005b5000
// TMyNumberText::`scalar deleting destructor'
TMyNumberText::~TMyNumberText() {}

// slot 0x7a — TNumberText::UpdateControlCachedIntFromWindowText override.
// FUNCTION: IMPERIALISM 0x005b5050
int TMyNumberText::UpdateControlCachedIntFromWindowText() {
  // TODO(partial 0x5b5050): the original fetches the control's text into a CString via
  // the text-query virtual and, when non-empty, routes it through the shared-string
  // town-value helpers (0x49eb00 / 0x5b6a80) instead of the base int parse. Ported as an
  // honest partial pending recovery of those helpers' owning classes.
  CString text;
  return 0;
}
