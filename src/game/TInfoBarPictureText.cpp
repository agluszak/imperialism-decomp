#include "game/TInfoBarPictureText.h"
// SYNTHETIC: IMPERIALISM 0x005b5ac0
// TInfoBarPictureText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5bb0
// TInfoBarPictureText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoBarPictureText, TInfoBarText)

TInfoBarPictureText::TInfoBarPictureText() {}

// SYNTHETIC: IMPERIALISM 0x005b5c60
// TInfoBarPictureText::`scalar deleting destructor'
TInfoBarPictureText::~TInfoBarPictureText() {}

// FUNCTION: IMPERIALISM 0x005b5cb0
undefined TInfoBarPictureText::SetTextAndLayoutRect(CString text, RECT* layoutRect) {
  if (EqualRect(layoutRect, &layoutRectA4) == 0) {
    CopyRect(&layoutRectA4, layoutRect);
    RECT clipRect;
    CopyRectFromBuildRectFromSlot158(&clipRect);
    InvalidateCityDialogRectRegion(&clipRect, 1);
    UpdateTextEntrySharedString(&text);
    RefreshControl();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b5dd0
undefined TInfoBarPictureText::DestructTInfoBarTextAndMaybeFree() {
  return 0;
}
