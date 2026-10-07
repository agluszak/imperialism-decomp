#include "game/ui_widgets/TInfoBarPictureText.h"

IMPLEMENT_DYNCREATE(TInfoBarPictureText, TInfoBarText)

// FUNCTION: IMPERIALISM 0x005b5c90
TInfoBarPictureText::~TInfoBarPictureText() {}

// FUNCTION: IMPERIALISM 0x005b5cb0
void TInfoBarPictureText::HotText(CString text, RECT* layoutRect) {
  if (EqualRect(layoutRect, &this->layoutRect) == 0) {
    CopyRect(&this->layoutRect, layoutRect);
    CRect clipRect;
    GetDrawableQDRect(&clipRect);
    InvalidateCityDialogRectRegion(&clipRect, 1);
    UpdateTextEntrySharedString(&text);
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005b5dd0
void TInfoBarPictureText::ClearTextAndLayoutRect(int) {
  layoutRect.left = 0;
  layoutRect.top = 0;
  layoutRect.right = 0;
  layoutRect.bottom = 0;

  CRect bounds;
  GetFrame(&bounds);
  CRect clipRect;
  CopyRect(&clipRect, &bounds);
  ownerContext->InvalidateCityDialogRectRegion(&clipRect, 1);

  CString empty;
  TStaticText::SetText(&empty);
  RefreshControl();
}
