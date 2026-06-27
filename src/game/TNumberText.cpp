#include "game/TNumberText.h"
#include "game/CMcWindow.h"
#include "game/buffered_stream.h"
#include "game/mfc.h"

extern "C" CRuntimeClass PTR_s_TNumberText_006496a8;

// FUNCTION: IMPERIALISM 0x00429500
TNumberText::TNumberText() : TEditText() {
  this->value = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00429530
// TNumberText::`scalar deleting destructor'
TNumberText::~TNumberText() {}
IMPLEMENT_DYNCREATE(TNumberText, TEditText)

// FUNCTION: IMPERIALISM 0x00491060
void TNumberText::ConstructTNumberTextBaseState(TControl* panel, int* offsetLayout, int* sizeLayout, int val, int field_a4_val, int field_a8_val) {
  this->InitializeTextEntryBaseAndOptionalStringResource(panel, offsetLayout, sizeLayout, 5, 5, -1, 0);
  this->field_9c = 0xff;
  this->SetControlValue(1);
  this->field_a8 = field_a8_val;
  this->field_a4 = field_a4_val;
  this->SetControlValue(val, 0);
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
  if (this->field_94 != nullptr) {
    CString textVal;
    this->field_94->GetWindowTextOrDelegateToOwner(&textVal);
    this->value = ParseSignedIntAndDiscardResult(const_cast<char*>((const char*)textVal));
  }
  return this->value;
}

// FUNCTION: IMPERIALISM 0x004912b0
TObject* TNumberText::ShallowClone() {
  TObject* cloned = this->ShallowFree();
  if (cloned != nullptr) {
    TNumberText* dest = static_cast<TNumberText*>(cloned);
    dest->CopyCityDialogStateFromSource(this);
    dest->field_94 = this->field_94;
    dest->field_98 = this->field_98;
    dest->field_9c = this->field_9c;
  }
  return cloned;
}
