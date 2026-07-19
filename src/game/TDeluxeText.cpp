#include "game/TDeluxeText.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x00430950
TDeluxeText::TDeluxeText() : TTEView(), cursorThemeCode98(0), cursorThemeCode9c(0), fieldA0(0) {}

// SYNTHETIC: IMPERIALISM 0x004309e0
// TDeluxeText::`scalar deleting destructor'
TDeluxeText::~TDeluxeText() {}
// SYNTHETIC: IMPERIALISM 0x005b5ee0
// TDeluxeText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5fd0
// TDeluxeText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDeluxeText, TTEView)

// FUNCTION: IMPERIALISM 0x005b5ff0
void TDeluxeText::ConstructTDeluxeTextBaseState(TView* panel, int* offsetLayout, int* sizeLayout,
                                                RECT* insetRect, TUiTextStyleDescriptor* style,
                                                short styleWord90) {
  ConstructTTEViewBaseState(0, panel, offsetLayout, sizeLayout, 5, 5, insetRect, style, styleWord90,
                            0, 1);
  cursorThemeCode98 = style->textColor;
  SetSelectedFlagAndState(0);
}

// FUNCTION: IMPERIALISM 0x005b6060
void TDeluxeText::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  field95 = 0;
  SetSelectedFlagAndState(0);
}

// FUNCTION: IMPERIALISM 0x005b60a0
void TDeluxeText::SetSelectedFlagAndState(char param_1) {
  field94 = param_1;
  SetState(param_1, 0);
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
    BuildInsetContentRect(&shadowRect);
    OffsetRect(&shadowRect, 1, 1);
    RenderControlStateTextBySelectionCode((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect,
                                          field90);
  }
  RECT mainRect;
  BuildInsetContentRect(&mainRect);
  SetQuickDrawColorAndSyncGlobals(cursorThemeCode98);
  RenderControlStateTextBySelectionCode((LPCSTR)textBuffer, textBuffer.GetLength(), &mainRect,
                                        field90);
}

// FUNCTION: IMPERIALISM 0x005b62a0
void TDeluxeText::ApplyTextStyleDescriptorAndMaybeRefresh(TUiTextStyleDescriptor* styleDescriptor,
                                                          int refreshFlag) {
  cursorThemeCode98 = styleDescriptor->textColor;
  SetTextStyleAndMaybeRefresh(styleDescriptor, static_cast<char>(refreshFlag));
}

// FUNCTION: IMPERIALISM 0x005b62e0
void TDeluxeText::BuildAndApplyTextStyleDescriptor(int unused, int pointSize, int themeCode) {
  TUiTextStyleDescriptor styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, themeCode);
  ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 1);
}

// FUNCTION: IMPERIALISM 0x005b6360
void TDeluxeText::SetTextEntryFromChars(const char* textChars, int textLength) {
  (void)textLength; // accepted but never read by the original body
  CString text(textChars);
  UpdateTextEntrySharedString(&text);
}

// FUNCTION: IMPERIALISM 0x005b63e0
int TDeluxeText::RecenterTextFromMeasuredWidthAndMaybeInvalidate(char refreshNow) {
  contentInsets68.bottom = 0;
  contentInsets68.top = 0;
  int measuredWidth = MeasureCurrentTextWidthInLayoutRect();
  int inset = 0;
  if (measuredWidth < frameHeight38) {
    inset = (frameHeight38 - measuredWidth) / 2;
  }
  contentInsets68.bottom = static_cast<short>(inset);
  contentInsets68.top = static_cast<short>(inset);
  if (refreshNow != 0) {
    RefreshControl();
  }
  return measuredWidth;
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
void TDeluxeText::BuildCityViewProductionControls_Impl(short codeGroup, short stringIndex) {
  CString text;
  g_pSimMgr->GetString(codeGroup, stringIndex - 1, &text);
  UpdateTextEntrySharedStringIfChanged(&text);
  RefreshControl();
}
