#include "game/TDeluxeText.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004309e0
// TDeluxeText::`scalar deleting destructor'
TDeluxeText::~TDeluxeText() {}
// SYNTHETIC: IMPERIALISM 0x005b5ee0
// TDeluxeText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5fd0
// TDeluxeText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDeluxeText, TTEView)

TDeluxeText::TDeluxeText() : TTEView(), cursorThemeCode98(0), cursorThemeCode9c(0), fieldA0(0) {}

// FUNCTION: IMPERIALISM 0x005b6060
void TDeluxeText::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005b60a0
void TDeluxeText::OrphanCallChain_C1_I08_005b60a0(char param_1) {
  // TODO(manifest): real body sets field_0x94 = param_1 then calls an
  // unresolved vtable slot (placeholder name
  // UpdateControlCachedIntFromWindowText_2a) with (param_1, 0) — slot not
  // yet mapped to a real method, left unimplemented rather than guessed.
  (void)param_1;
}

// FUNCTION: IMPERIALISM 0x005b60d0
void TDeluxeText::SetTextFromUiStringResourceId(short stringId) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceById(&text, stringId);
  this->UpdateTextEntrySharedStringAndMaybeNotify(&text, 1);
}

// FUNCTION: IMPERIALISM 0x005b6170
void TDeluxeText::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CString textBuffer;
  AssignSharedStringFromField84(&textBuffer);
  if (fieldA0 != 0) {
    SetQuickDrawColorAndSyncGlobals(cursorThemeCode9c);
    RECT shadowRect;
    BuildRectFromSlot158(&shadowRect);
    OffsetRect(&shadowRect, 1, 1);
    RenderControlStateTextBySelectionCode((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect,
                                          field90);
  }
  RECT mainRect;
  BuildRectFromSlot158(&mainRect);
  SetQuickDrawColorAndSyncGlobals(cursorThemeCode98);
  RenderControlStateTextBySelectionCode((LPCSTR)textBuffer, textBuffer.GetLength(), &mainRect,
                                        field90);
}

// FUNCTION: IMPERIALISM 0x005b62a0
void TDeluxeText::ConstructTMapKeyBaseState_Impl(int* styleDescriptor, int unusedFlag) {
  // TODO(manifest): real body sets field_0x98 = *(int*)(styleDescriptor + 6),
  // then forwards to two unresolved low-level style/font helpers
  // (func_0x0040350d(0xf, styleDescriptor, unusedFlag) and
  // func_0x004093a4(0, result)) — left unimplemented rather than guessed.
  (void)styleDescriptor;
  (void)unusedFlag;
}

// FUNCTION: IMPERIALISM 0x005b62e0
void TDeluxeText::WrapperFor_thunk_BuildUiTextStyleDescriptor_At005b62e0() {
  // TODO(manifest): real body builds a local 6-byte style descriptor (via an
  // unresolved helper), stores it into field_0x98, then forwards to the same
  // pair of unresolved style/font helpers as ConstructTMapKeyBaseState_Impl —
  // left unimplemented rather than guessed.
}

// FUNCTION: IMPERIALISM 0x005b6360
void TDeluxeText::Helper_Uses_ConstructSharedStringFromCStrOrResourceId_At005b6360(
    CString param_1) {
  UpdateTextEntrySharedString(&param_1);
}

// FUNCTION: IMPERIALISM 0x005b63e0
undefined TDeluxeText::RecenterTextFromMeasuredWidthAndMaybeInvalidate(char param_1) {
  (void)param_1;
  // TODO(manifest): real body measures the current text's rendered width via
  // an unresolved helper (func_0x004065e1), recenters field_0x74/field_0x6c
  // from (field38 - measuredWidth)/2, conditionally calls RefreshControl(),
  // and returns a packed (measuredWidth, someFlag) pair — left unimplemented
  // rather than guessed.
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6480
void TDeluxeText::UpdateTextEntrySharedString(CString* text) {
  UpdateTextEntrySharedStringIfChanged(text);
}

// FUNCTION: IMPERIALISM 0x005b64a0
void TDeluxeText::UpdateTextEntrySharedStringAndMaybeNotify(CString* text, char notifyFlag) {
  UpdateTextEntrySharedStringIfChanged(text);
  if (notifyFlag != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005b64e0
void TDeluxeText::BuildCityViewProductionControls_Impl() {
  // TODO(manifest): real body builds a CString via
  // g_pLocalizationTable's vtable slot 0x10.4, assigns it through
  // UpdateTextEntrySharedStringIfChanged, then calls RefreshControl() —
  // g_pLocalizationTable's class isn't recovered yet, left unimplemented
  // rather than guessed.
}
