#include "game/ui_widgets/TDropShadowText.h"

#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x005b54a0
// TDropShadowText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5570
// TDropShadowText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDropShadowText, TPictureText)

// FUNCTION: IMPERIALISM 0x005b5590
TDropShadowText::TDropShadowText() : TPictureText(), shadowColor94(0) {}

// SYNTHETIC: IMPERIALISM 0x005b5600
// TDropShadowText::`scalar deleting destructor'
TDropShadowText::~TDropShadowText() {}

// Widen the paint clip by 1px on the top-left (room for the shadow's -1,-1 offset),
// paint the base text through it, then draw the shadow-colored copy offset by (-1,-1)
// before restoring the DC's clip region.
// FUNCTION: IMPERIALISM 0x005b5650
void TDropShadowText::Draw(RECT* rectBuffer) {
  CRect clipRect;
  GetQDExtent(&clipRect);
  clipRect.left--;
  clipRect.top--;

  CDC* dc = GetActiveQuickDrawDc();
  {
    CRgn clipRgn;
    clipRgn.Attach(::CreateRectRgnIndirect(&clipRect));
    dc->SelectClipRgn(&clipRgn);
    clipRgn.DeleteObject();
  }

  TStaticText::Draw(rectBuffer);

  SetQuickDrawColorAndSyncGlobals(shadowColor94);
  CString textBuffer;
  CopyTextTo(&textBuffer);
  CRect shadowRect;
  BuildInsetContentRect(&shadowRect);
  shadowRect.left--;
  shadowRect.top--;
  shadowRect.right--;
  shadowRect.bottom--;
  DrawTextAligned((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect, textAlignmentCode);

  dc->SelectClipRgn(0);
}
