#include "game/ui_widgets/TDeluxeText.h"

#include "game/gfx/TResourceMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00430950
TDeluxeText::TDeluxeText()
    : TTEView(), textColor(0), shadowTextColor(0), dropShadowEnabled(false) {}

// FUNCTION: IMPERIALISM 0x00430a10
TDeluxeText::~TDeluxeText() {}

IMPLEMENT_DYNCREATE(TDeluxeText, TTEView)

// FUNCTION: IMPERIALISM 0x005b5ff0
void TDeluxeText::IDeluxeText(TView* panel, int* offsetLayout, int* sizeLayout, RECT* insetRect,
                              TextStyle* style, short styleWord90) {
  ITEView(nullptr, panel, offsetLayout, sizeLayout, 5, 5, insetRect, style, styleWord90, 0, true);
  textColor = style->textColor;
  EnableEditing(0);
}

// FUNCTION: IMPERIALISM 0x005b6060
void TDeluxeText::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  field95 = 0;
  EnableEditing(0);
}

// FUNCTION: IMPERIALISM 0x005b60a0
void TDeluxeText::EnableEditing(char enable) {
  editingEnabled = enable;
  ViewEnable(enable, 0);
}

// FUNCTION: IMPERIALISM 0x005b60d0
void TDeluxeText::LoadTextResource(short stringId) {
  CString text;
  g_pResourceMgr->LoadUiStringResourceById(&text, stringId);
  this->UpdateTextEntrySharedStringAndMaybeNotify(&text, true);
}

// FUNCTION: IMPERIALISM 0x005b6170
void TDeluxeText::Draw(RECT* rectBuffer) {
  CString textBuffer;
  CopyTextTo(&textBuffer);
  if (dropShadowEnabled) {
    SetQuickDrawColorAndPropagateIfChanged(shadowTextColor);
    CRect shadowRect;
    BuildInsetContentRect(&shadowRect);
    OffsetRect(&shadowRect, 1, 1);
    ImageText((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect, textAlignmentCode);
  }
  CRect mainRect;
  BuildInsetContentRect(&mainRect);
  SetQuickDrawColorAndPropagateIfChanged(textColor);
  ImageText((LPCSTR)textBuffer, textBuffer.GetLength(), &mainRect, textAlignmentCode);
}

// FUNCTION: IMPERIALISM 0x005b62a0
void TDeluxeText::SetTextStyle(const TextStyle& style, bool refreshNow) {
  textColor = style.textColor;
  SetOneStyle(0, GetNumberOfChars(), 0xf, style, refreshNow);
}

// FUNCTION: IMPERIALISM 0x005b62e0
void TDeluxeText::SetTextStyle(int fontStyleFlags, int pointSize, int themeCode) {
  TextStyle style;
  style.textColor = 0;
  BuildUiTextStyleDescriptor(&style, fontStyleFlags, pointSize, themeCode);
  textColor = style.textColor;
  SetOneStyle(0, GetNumberOfChars(), 0xf, style, true);
}

// FUNCTION: IMPERIALISM 0x005b6360
void TDeluxeText::SetTextEntryFromChars(const char* textChars, int textLength) {
  (void)textLength; // accepted but never read by the original body
  CString text(textChars);
  UpdateTextEntrySharedString(&text);
}

// FUNCTION: IMPERIALISM 0x005b63e0
short TDeluxeText::CenterVertically(bool refreshNow) {
  contentInsets.bottom = 0;
  contentInsets.top = 0;
  int measuredHeight = MeasureCurrentTextHeightInLayoutRect();
  short inset;
  if (measuredHeight < frameHeight) {
    inset = static_cast<short>((frameHeight - measuredHeight) / 2);
  } else {
    inset = 0;
  }
  contentInsets.bottom = inset;
  contentInsets.top = inset;
  CRect textRect(0, inset, frameWidth, frameHeight - inset);
  StuffTERects(textRect);
  if (refreshNow) {
    RefreshControl();
  }
  return measuredHeight;
}

// FUNCTION: IMPERIALISM 0x005b6480
void TDeluxeText::UpdateTextEntrySharedString(CString* text) {
  TStaticText::SetText(text);
}

// FUNCTION: IMPERIALISM 0x005b64a0
void TDeluxeText::UpdateTextEntrySharedStringAndMaybeNotify(CString* text, bool notifyFlag) {
  TStaticText::SetText(text);
  if (notifyFlag) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005b64e0
void TDeluxeText::BuildCityViewProductionControls_Impl(short codeGroup, short stringIndex) {
  CString text;
  g_pSimMgr->GetString(codeGroup, stringIndex - 1, &text);
  TStaticText::SetText(&text);
  RefreshControl();
}
