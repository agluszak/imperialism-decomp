#include "game/TDropShadowText.h"

#include "game/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x005b54a0
// TDropShadowText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5570
// TDropShadowText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDropShadowText, TPictureText)

// FUNCTION: IMPERIALISM 0x005b5590
TDropShadowText::TDropShadowText() : TPictureText(), shadowThemeCode94(0) {}

// SYNTHETIC: IMPERIALISM 0x005b5600
// TDropShadowText::`scalar deleting destructor'
TDropShadowText::~TDropShadowText() {}

// Widen the paint clip by 1px on the top-left (room for the shadow's -1,-1 offset),
// paint the base text through it, then draw the shadow-colored copy offset by (-1,-1)
// before restoring the DC's clip region.
// FUNCTION: IMPERIALISM 0x005b5650
void TDropShadowText::ApplyRectSlot110(RECT* rectBuffer) {
  RECT clipRect;
  BuildRectFromSlot158(&clipRect);
  clipRect.left--;
  clipRect.top--;

  CDC* dc = GetActiveQuickDrawDc();
  {
    CRgn clipRgn;
    clipRgn.Attach(::CreateRectRgnIndirect(&clipRect));
    dc->SelectClipRgn(&clipRgn);
    clipRgn.DeleteObject();
  }

  TStaticText::ApplyRectSlot110(rectBuffer);

  SetQuickDrawColorAndSyncGlobals(shadowThemeCode94);
  CString textBuffer;
  CopyTextTo(&textBuffer);
  RECT shadowRect;
  BuildInsetContentRect(&shadowRect);
  shadowRect.left--;
  shadowRect.top--;
  shadowRect.right--;
  shadowRect.bottom--;
  DrawTextAligned((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect, textAlignmentCode);

  dc->SelectClipRgn(0);
}
