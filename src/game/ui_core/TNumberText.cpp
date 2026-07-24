#include "game/ui_core/TNumberText.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/mfc.h"
#include <stdlib.h>

// FUNCTION: IMPERIALISM 0x00429500
TNumberText::TNumberText() : TEditText() {
  this->value = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00429530
// TNumberText::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00429560
TNumberText::~TNumberText() {}
// SYNTHETIC: IMPERIALISM 0x00490ed0
// TNumberText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00491040
// TNumberText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberText, TEditText)

// FUNCTION: IMPERIALISM 0x00491060
void TNumberText::INumberText(TView* panel, int* offsetLayout, int* sizeLayout, int value,
                              int minimumValue, int maximumValue) {
  this->IStaticText(panel, offsetLayout, sizeLayout, 5, 5, -1, 0);
  this->maxCharacterCount = 0xff;
  this->SetEnable(1);
  this->maximumValue = maximumValue;
  this->minimumValue = minimumValue;
  this->SetControlValue(value, 0);
}

// FUNCTION: IMPERIALISM 0x004910e0
void TNumberText::SetControlValue(int val, int refresh) {
  this->value = val;
  CString formatted;
  formatted.Format("%d", val);
  this->InitDialogWindowAndSyncTitleIfChanged(&formatted, refresh);
}

// FUNCTION: IMPERIALISM 0x004911c0
int TNumberText::UpdateControlCachedIntFromWindowText() {
  if (this->editWindow != nullptr) {
    CString textVal;
    this->editWindow->GetWindowText(textVal);
    this->value = atoi(textVal);
  }
  return this->value;
}

// FUNCTION: IMPERIALISM 0x004912b0
TObject* TNumberText::ShallowClone() {
  TObject* cloned = this->ShallowFree();
  TNumberText* dest = static_cast<TNumberText*>(cloned);
  dest->CopyViewStateFromSource(this);
  dest->editWindow = this->editWindow;
  dest->editFont = this->editFont;
  dest->maxCharacterCount = this->maxCharacterCount;
  return cloned;
}
