#include "game/ui_widgets/TDropShadowText.h"

#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TDropShadowText, TPictureText)

// FUNCTION: IMPERIALISM 0x005b5590
TDropShadowText::TDropShadowText() : TPictureText(), shadowColor(0) {}

// FUNCTION: IMPERIALISM 0x005b5630
TDropShadowText::~TDropShadowText() {}

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

  SetQuickDrawColorAndSyncGlobals(shadowColor);
  CString textBuffer;
  CopyTextTo(&textBuffer);
  CRect shadowRect;
  BuildInsetContentRect(&shadowRect);
  shadowRect.left--;
  shadowRect.top--;
  shadowRect.right--;
  shadowRect.bottom--;
  ImageText((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect, textAlignmentCode);

  dc->SelectClipRgn(0);
}
