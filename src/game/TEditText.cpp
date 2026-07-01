#include "game/TEditText.h"
#include "game/CMcWindow.h"
#include "game/TObject.h"
// SYNTHETIC: IMPERIALISM 0x00490210
// TEditText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00490380
// TEditText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEditText, TStaticText)

// FUNCTION: IMPERIALISM 0x004903a0
TEditText::TEditText() : TStaticText() {
  this->hasCommandTagResource = 13;
  CString* textPtr = new CString();
  *reinterpret_cast<CString**>(&this->text) = textPtr;
  this->field_94 = nullptr;
  this->field_98 = 0;
  this->field_9c = 0xff;
  this->flag4d = 0;
}

// FUNCTION: IMPERIALISM 0x004904d0
TEditText::~TEditText() {
  if (this->field_94 != nullptr) {
    delete this->field_94;
    this->field_94 = nullptr;
  }
  if (this->field_98 != 0) {
    delete reinterpret_cast<TObject*>(this->field_98);
    this->field_98 = 0;
  }
  CString* textPtr = *reinterpret_cast<CString**>(&this->text);
  if (textPtr != nullptr) {
    textPtr->~CString();
    free(textPtr);
  }
}

// FUNCTION: IMPERIALISM 0x00490650
void TEditText::CallVoidSlotA0() {
}

// FUNCTION: IMPERIALISM 0x004906a0
void TEditText::ApplyRectSlot110(RECT* rectBuffer) {
}

// FUNCTION: IMPERIALISM 0x004906d0
char TEditText::GetBoolSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004906f0
void TEditText::SetControlValue(int value) {
}

// FUNCTION: IMPERIALISM 0x00490730
void TEditText::SetEnabled(int enabledState, int refreshFlag) {
}

// FUNCTION: IMPERIALISM 0x004907a0
void TEditText::DispatchSlot9CToLinkedChildren() {
}

// FUNCTION: IMPERIALISM 0x00490a50
undefined TEditText::SetEditSelectionAndScrollCaret() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490aa0
char TEditText::ActivateCityProductionViewIfAllowed() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490ad0
void TEditText::Free() {
}

// FUNCTION: IMPERIALISM 0x00490bc0
char TEditText::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490c10
void TEditText::HandleCityProductionNoOp() {
}

// FUNCTION: IMPERIALISM 0x00490c30
void TEditText::vmethod_0081(int) {
}

// FUNCTION: IMPERIALISM 0x00490c70
undefined TEditText::WrapperFor_StringShared_AssignFromPtr_At00490c70(CString * param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490cb0
undefined TEditText::OrphanCallChain_C1_I09_0048ff70(short themeCode, char refreshFlag) {
  (void)themeCode;
  (void)refreshFlag;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490cf0
void TEditText::InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag) {
  (void)newText;
  (void)refreshFlag;
}

// FUNCTION: IMPERIALISM 0x00490e50
void TEditText::RecomputeAbsolutePositionRecursive() {
}

// SYNTHETIC: IMPERIALISM 0x00492f30
// TEditText::`scalar deleting destructor'

