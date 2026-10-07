#include "game/tactical_ui/TTechHistoryView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TScrollView.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00460170
TTechHistoryView::~TTechHistoryView() {}

IMPLEMENT_DYNCREATE(TTechHistoryView, TView)

// FUNCTION: IMPERIALISM 0x005b22c0
void TTechHistoryView::StuffValues(short techId) {
  COLORREF mainStyle = 0;
  COLORREF shadowStyle = 0;
  ResolveUiThemeColor(0x2b6a, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);
  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TDropShadowText* titleControl = static_cast<TDropShadowText*>(FindSubView(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextWithStrListID(0x2712, static_cast<short>(techId + 1), true);
  ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0x12, 0x2b6a, 0x2b68);

  TPicture* pictControl = static_cast<TPicture*>(FindSubView(kControlTagPict));
  pictControl->AssertValid();
  pictControl->SetPictureRsrcID(static_cast<short>(techId + 0x944), 1);

  TScrollView* scrollView = static_cast<TScrollView*>(FindSubView(kControlTagScvw));
  scrollView->AssertValid();

  TDeluxeText* descText = new TDeluxeText();
  int offset[2] = {0, 0};
  int size[2] = {scrollView->frameWidth - 0x19, frameHeight};
  CRect zeroRect(0, 0, 0, 0);
  descText->IDeluxeText(scrollView, offset, size, &zeroRect, &style, -2);
  descText->textColor = mainStyle;
  descText->LoadTextResource(static_cast<short>(techId + 0x8fc));

  int measuredHeight = descText->MeasureCurrentTextHeightInLayoutRect();
  CRect descBounds;
  descText->GetFrame(&descBounds);
  descBounds.bottom = descBounds.top + static_cast<short>(measuredHeight);
  descText->SetFrame(&descBounds, true);

  scrollView->contentView = descText;
  scrollView->Reset();

  CPoint titleLayout(0x8c, 0xf0 - titleControl->frameHeight / 2);
  titleControl->Locate(titleLayout, true);
}
