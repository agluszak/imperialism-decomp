#include "game/ui_core/TNumberText.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/mfc.h"
#include <stdlib.h>

// Destructors are compiler-generated (implicit) from real inheritance.
// FUNCTION: IMPERIALISM 0x00429560
TNumberText::~TNumberText() {}

IMPLEMENT_DYNCREATE(TNumberText, TEditText)

// FUNCTION: IMPERIALISM 0x00491060
void TNumberText::INumberText(TView* panel, int* offsetLayout, int* sizeLayout, int value,
                              int minimumValue, int maximumValue) {
  IEditText(panel, offsetLayout, sizeLayout, 0xff);
  this->maximumValue = maximumValue;
  this->minimumValue = minimumValue;
  SetControlValue(value, 0);
}

// FUNCTION: IMPERIALISM 0x004910e0
void TNumberText::SetControlValue(int val, int refresh) {
  value = val;
  CString formatted;
  formatted.Format("%d", val);
  InitDialogWindowAndSyncTitleIfChanged(&formatted, refresh);
}

// FUNCTION: IMPERIALISM 0x004911c0
int TNumberText::UpdateControlCachedIntFromWindowText() {
  if (editWindow != NULL) {
    CString textVal;
    editWindow->GetWindowText(textVal);
    value = atoi(textVal);
  }
  return value;
}

// FUNCTION: IMPERIALISM 0x00491260
void TEditText::CopyEditTextStateFromSource(TEditText* source) {
  CopyViewStateFromSource(source);
  editWindow = source->editWindow;
  editFont = source->editFont;
  maxCharacterCount = source->maxCharacterCount;
}

// FUNCTION: IMPERIALISM 0x004912b0
TObject* TNumberText::ShallowClone() {
  TObject* cloned = ShallowFree();
  TNumberText* dest = static_cast<TNumberText*>(cloned);
  dest->CopyViewStateFromSource(this);
  dest->editWindow = editWindow;
  dest->editFont = editFont;
  dest->maxCharacterCount = maxCharacterCount;
  return cloned;
}
