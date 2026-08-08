#include "game/ui_widgets/TInfoBarPictureText.h"
// SYNTHETIC: IMPERIALISM 0x005b5ac0
// TInfoBarPictureText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5bb0
// TInfoBarPictureText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoBarPictureText, TInfoBarText)

// SYNTHETIC: IMPERIALISM 0x005b5c60
// TInfoBarPictureText::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b5c90
TInfoBarPictureText::~TInfoBarPictureText() {}

// FUNCTION: IMPERIALISM 0x005b5cb0
void TInfoBarPictureText::SetTextAndLayoutRect(CString text, RECT* layoutRect) {
  if (EqualRect(layoutRect, &layoutRectA4) == 0) {
    CopyRect(&layoutRectA4, layoutRect);
    CRect clipRect;
    GetDrawableQDRect(&clipRect);
    InvalidateCityDialogRectRegion(&clipRect, 1);
    UpdateTextEntrySharedString(&text);
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005b5dd0
void TInfoBarPictureText::ClearTextAndLayoutRect(int) {
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;

  CRect bounds;
  QueryBounds(&bounds);
  CRect clipRect;
  CopyRect(&clipRect, &bounds);
  ownerContext->InvalidateCityDialogRectRegion(&clipRect, 1);

  CString empty;
  TStaticText::SetText(&empty);
  RefreshControl();
}
