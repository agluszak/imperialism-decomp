#include "game/ui_screens/TTextPictureButton.h"

#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x005724e0
// TTextPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005725b0
// TTextPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTextPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005725d0
TTextPictureButton::TTextPictureButton()
    : TUpDownPictureButton(), pointSize98(0), themeCode9A(0), themeCode9C(0) {}

// SYNTHETIC: IMPERIALISM 0x00572670
// TTextPictureButton::`scalar deleting destructor'
TTextPictureButton::~TTextPictureButton() {}

// FUNCTION: IMPERIALISM 0x00572710
void TTextPictureButton::InitializeTextPictureButtonAndTextStyle(TView* panel, int* offsetLayout,
                                                                 int* sizeLayout, short pictureId,
                                                                 CString* text, short pointSize,
                                                                 short themeCodeA,
                                                                 short themeCodeC) {
  InitializePictureEntryBaseAndRefresh(panel, offsetLayout, sizeLayout, 5, 5, pictureId);
  buttonText = *text;
  pointSize98 = pointSize;
  themeCode9A = themeCodeA;
  themeCode9C = themeCodeC;
}

// Draws the button label twice, offset by one pixel down-right for a drop-shadow/
// embossed look at themeCode9C, then again at the caret position (no offset) at
// themeCode9A. Both passes center the text in the button's frame, nudged by 1px when
// the button is pressed (controlState64 != 0, TControl's mode byte).
// FUNCTION: IMPERIALISM 0x00572790
void TTextPictureButton::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  int pressedOffset = (controlState64 != 0) ? 1 : 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, pointSize98, themeCode9C);
  COLORREF shadowColor;
  ResolveUiThemeColor(themeCode9C, &shadowColor);
  SetQuickDrawColorAndSyncGlobals(shadowColor);

  short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&buttonText);
  int halfTextWidth = textWidth / 2;

  CDC* activeDc = GetActiveQuickDrawDc();
  SIZE extent;
  GetTextExtentPointA(activeDc->GetSafeHdc(), (LPCSTR)buttonText, buttonText.GetLength(), &extent);
  int quarterHeight = extent.cy / 4;

  SetQuickDrawTextOriginWithContextOffset(
      static_cast<short>(frameWidth34 / 2 - halfTextWidth + 1 + pressedOffset),
      static_cast<short>(frameHeight38 / 2 + quarterHeight + 1 + pressedOffset));
  DrawTextWithCachedQuickDrawStyleState(&buttonText);

  COLORREF textColor;
  ResolveUiThemeColor(themeCode9A, &textColor);
  SetQuickDrawColorAndSyncGlobals(textColor);

  SetQuickDrawTextOriginWithContextOffset(
      static_cast<short>(frameWidth34 / 2 - halfTextWidth + pressedOffset),
      static_cast<short>(frameHeight38 / 2 + quarterHeight + pressedOffset));
  DrawTextWithCachedQuickDrawStyleState(&buttonText);
}
