#include "game/TDeluxeText.h"

// SYNTHETIC: IMPERIALISM 0x004309e0
// TDeluxeText::`scalar deleting destructor'
TDeluxeText::~TDeluxeText() {}
// SYNTHETIC: IMPERIALISM 0x005b5ee0
// TDeluxeText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5fd0
// TDeluxeText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDeluxeText, TTEView)

TDeluxeText::TDeluxeText() {}

// FUNCTION: IMPERIALISM 0x005b6060
void TDeluxeText::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005b60a0
undefined TDeluxeText::OrphanCallChain_C1_I08_005b60a0(char param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b60d0
undefined TDeluxeText::InitializeTechHistoryViewTitleAndMapKeyControls_Impl() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6170
void TDeluxeText::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x005b62a0
undefined TDeluxeText::ConstructTMapKeyBaseState_Impl(void* styleDescriptor, int unusedFlag) {
  (void)styleDescriptor;
  (void)unusedFlag;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b62e0
undefined TDeluxeText::WrapperFor_thunk_BuildUiTextStyleDescriptor_At005b62e0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6360
undefined
TDeluxeText::Helper_Uses_ConstructSharedStringFromCStrOrResourceId_At005b6360(CString param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b63e0
undefined TDeluxeText::RecenterTextFromMeasuredWidthAndMaybeInvalidate(char param_1) {
  (void)param_1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6480
undefined TDeluxeText::UpdateTextEntrySharedString(CString* text) {
  UpdateTextEntrySharedStringIfChanged(text);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b64a0
undefined TDeluxeText::UpdateTextEntrySharedStringAndMaybeNotify(CString* text, char notifyFlag) {
  UpdateTextEntrySharedStringIfChanged(text);
  if (notifyFlag != 0) {
    RefreshControl();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b64e0
undefined TDeluxeText::BuildCityViewProductionControls_Impl() {
  return 0;
}
