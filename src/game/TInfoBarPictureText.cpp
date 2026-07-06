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
void TInfoBarPictureText::ClearTextAndLayoutRect() {
  // TODO: picture-variant of the slot-0x7f clear -- zeroes layoutRectA4, then measures a
  // rect via the picture's slot-0x4b getter, CopyRect + invalidate, and calls slot 0x39.
  // Body not yet ported (unresolved slot-0x4b/0x39 getters); renamed off the bogus
  // Destruct*AndMaybeFree name so it is a real virtual, not a construction bridge.
}
