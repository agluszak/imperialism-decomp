#include "game/TTechHistoryView.h"

#include "game/TDeluxeText.h"
#include "game/TDropShadowText.h"
#include "game/TPicture.h"
#include "game/TScrollView.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00460140
// TTechHistoryView::`scalar deleting destructor'
TTechHistoryView::~TTechHistoryView() {}
// SYNTHETIC: IMPERIALISM 0x005b2230
// TTechHistoryView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b22a0
// TTechHistoryView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechHistoryView, TView)

TTechHistoryView::TTechHistoryView() {}

// FUNCTION: IMPERIALISM 0x005b22c0
void TTechHistoryView::PopulateTechHistory(short techId) {
  COLORREF mainStyle = 0;
  COLORREF shadowStyle = 0;
  ResolveUiThemeColor(0x2b6a, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);
  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TDropShadowText* titleControl =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextFromStringResource(0x2712, static_cast<short>(techId + 1), 1);
  ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0x12, 0x2b6a, 0x2b68);

  TPicture* pictControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagPict));
  pictControl->AssertValid();
  pictControl->SetPictureResourceIdAndRefresh(static_cast<short>(techId + 0x944), 1);

  TScrollView* scrollView = static_cast<TScrollView*>(ResolveControlByTag(kControlTagScvw));
  scrollView->AssertValid();

  TDeluxeText* descText = new TDeluxeText();
  int offset[2] = {0, 0};
  int size[2] = {scrollView->frameWidth34 - 0x19, frameHeight38};
  CRect zeroRect(0, 0, 0, 0);
  descText->InitializeDeluxeText(scrollView, offset, size, &zeroRect, &style, -2);
  descText->textColor98 = mainStyle;
  descText->SetTextFromUiStringResourceId(static_cast<short>(techId + 0x8fc));

  int measuredHeight = descText->MeasureCurrentTextHeightInLayoutRect();
  CRect descBounds;
  descText->QueryBounds(&descBounds);
  descBounds.bottom = descBounds.top + static_cast<short>(measuredHeight);
  descText->ApplyBounds(&descBounds, 1);

  scrollView->contentView60 = descText;
  scrollView->SyncBoundedValueAndToggleControlStates();

  int titleLayout[2] = {0x8c, 0xf0 - titleControl->frameHeight38 / 2};
  titleControl->CaptureLayoutF0(titleLayout, 1);
}
