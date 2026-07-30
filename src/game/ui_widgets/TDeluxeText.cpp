#include "game/ui_widgets/TDeluxeText.h"

#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00430950
TDeluxeText::TDeluxeText()
    : TTEView(), textColor98(0), shadowTextColor9C(0), dropShadowEnabledA0(false) {}

// SYNTHETIC: IMPERIALISM 0x004309e0
// TDeluxeText::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00430a10
TDeluxeText::~TDeluxeText() {}
// SYNTHETIC: IMPERIALISM 0x005b5ee0
// TDeluxeText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5fd0
// TDeluxeText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDeluxeText, TTEView)

// FUNCTION: IMPERIALISM 0x005b5ff0
void TDeluxeText::IDeluxeText(TView* panel, int* offsetLayout, int* sizeLayout, RECT* insetRect,
                              TextStyle* style, short styleWord90) {
  ITEView(nullptr, panel, offsetLayout, sizeLayout, 5, 5, insetRect, style, styleWord90, 0, 1);
  textColor98 = style->textColor;
  SetSelectedFlagAndState(0);
}

// FUNCTION: IMPERIALISM 0x005b6060
void TDeluxeText::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  field95 = 0;
  SetSelectedFlagAndState(0);
}

// FUNCTION: IMPERIALISM 0x005b60a0
void TDeluxeText::SetSelectedFlagAndState(char param_1) {
  field94 = param_1;
  ViewEnable(param_1, 0);
}

// FUNCTION: IMPERIALISM 0x005b60d0
void TDeluxeText::SetTextFromUiStringResourceId(short stringId) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceById(&text, stringId);
  this->UpdateTextEntrySharedStringAndMaybeNotify(&text, 1);
}

// FUNCTION: IMPERIALISM 0x005b6170
void TDeluxeText::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  CString textBuffer;
  CopyTextTo(&textBuffer);
  if (dropShadowEnabledA0) {
    SetQuickDrawColorAndPropagateIfChanged(shadowTextColor9C);
    CRect shadowRect;
    BuildInsetContentRect(&shadowRect);
    OffsetRect(&shadowRect, 1, 1);
    DrawTextAligned((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect, textAlignmentCode);
  }
  CRect mainRect;
  BuildInsetContentRect(&mainRect);
  SetQuickDrawColorAndPropagateIfChanged(textColor98);
  DrawTextAligned((LPCSTR)textBuffer, textBuffer.GetLength(), &mainRect, textAlignmentCode);
}

// FUNCTION: IMPERIALISM 0x005b62a0
void TDeluxeText::SetTextStyle(const TextStyle& style, unsigned char refreshNow) {
  textColor98 = style.textColor;
  SetOneStyle(0, GetNumberOfChars(), 0xf, style, refreshNow);
}

// FUNCTION: IMPERIALISM 0x005b62e0
void TDeluxeText::SetTextStyle(int fontStyleFlags, int pointSize, int themeCode) {
  TextStyle style;
  style.textColor = 0;
  BuildUiTextStyleDescriptor(&style, fontStyleFlags, pointSize, themeCode);
  textColor98 = style.textColor;
  SetOneStyle(0, GetNumberOfChars(), 0xf, style, 1);
}

// FUNCTION: IMPERIALISM 0x005b6360
void TDeluxeText::SetTextEntryFromChars(const char* textChars, int textLength) {
  (void)textLength; // accepted but never read by the original body
  CString text(textChars);
  UpdateTextEntrySharedString(&text);
}

// FUNCTION: IMPERIALISM 0x005b63e0
short TDeluxeText::CenterVertically(unsigned char refreshNow) {
  contentInsets68.bottom = 0;
  contentInsets68.top = 0;
  int measuredHeight = MeasureCurrentTextHeightInLayoutRect();
  short inset;
  if (measuredHeight < frameHeight38) {
    inset = static_cast<short>((frameHeight38 - measuredHeight) / 2);
  } else {
    inset = 0;
  }
  contentInsets68.bottom = inset;
  contentInsets68.top = inset;
  CRect textRect(0, inset, frameWidth34, frameHeight38 - inset);
  StuffTERects(textRect);
  if (refreshNow != 0) {
    RefreshControl();
  }
  return measuredHeight;
}

// FUNCTION: IMPERIALISM 0x005b6480
void TDeluxeText::UpdateTextEntrySharedString(CString* text) {
  SetText(text);
}

// FUNCTION: IMPERIALISM 0x005b64a0
void TDeluxeText::UpdateTextEntrySharedStringAndMaybeNotify(CString* text, char notifyFlag) {
  SetText(text);
  if (notifyFlag != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005b64e0
void TDeluxeText::BuildCityViewProductionControls_Impl(short codeGroup, short stringIndex) {
  CString text;
  g_pSimMgr->GetString(codeGroup, stringIndex - 1, &text);
  SetText(&text);
  RefreshControl();
}
