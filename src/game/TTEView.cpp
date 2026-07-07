#include "game/TTEView.h"

#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0045ad70
// TTEView::`scalar deleting destructor'
TTEView::~TTEView() {}
// SYNTHETIC: IMPERIALISM 0x00485fb0
// TTEView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486030
// TTEView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTEView, TStaticText)

TTEView::TTEView() {}

// FUNCTION: IMPERIALISM 0x004860e0
int TTEView::MeasureCurrentTextWidthInLayoutRect() {
  CDC dc;
  dc.Attach(CreateCompatibleDC(static_cast<HDC>(0)));
  CFont* font = UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(&textStyle78);
  CFont* oldFont = dc.SelectObject(font);
  RECT bounds;
  BuildRectFromSlot158(&bounds);
  bounds.left += field68;
  bounds.top += field6C;
  bounds.right -= field70;
  bounds.bottom -= field74;
  dc.DrawText(*text, text->GetLength(), &bounds, 0xd10);
  dc.SelectObject(oldFont);
  return bounds.right - bounds.left;
}

// FUNCTION: IMPERIALISM 0x0061f342
void TTEView::DeflateRect(RECT* margins) {
  RECT* rect = reinterpret_cast<RECT*>(this);
  rect->left += margins->left;
  rect->top += margins->top;
  rect->right -= margins->right;
  rect->bottom -= margins->bottom;
}
