#include "game/ui_core/TTEView.h"

#include "game/ui_core/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x0045ad20
TTEView::TTEView() {}
// FUNCTION: IMPERIALISM 0x0045ad50
TTEView::~TTEView() {}

// SYNTHETIC: IMPERIALISM 0x0045ad70
// TTEView::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00485fb0
// TTEView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486030
// TTEView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTEView, TStaticText)

// FUNCTION: IMPERIALISM 0x00486050
void TTEView::InitializeTextEntryView(int unusedA, TView* panel, int* offsetLayout, int* sizeLayout,
                                      int layoutParam5, int layoutParam6, RECT* insetRect,
                                      TextStyle* style, short styleWord90, int unusedB,
                                      int unusedC) {
  (void)unusedA;
  (void)unusedB;
  (void)unusedC;
  InitializeTextEntryBaseAndOptionalStringResource(panel, offsetLayout, sizeLayout, layoutParam5,
                                                   layoutParam6, -1, 0);
  contentInsets68.left = insetRect->left;
  contentInsets68.top = insetRect->top;
  contentInsets68.right = insetRect->right;
  contentInsets68.bottom = insetRect->bottom;
  textStyle78 = *style;
  textAlignmentCode = styleWord90;
}

// FUNCTION: IMPERIALISM 0x004860e0
int TTEView::MeasureCurrentTextHeightInLayoutRect() {
  CDC dc;
  dc.Attach(CreateCompatibleDC(static_cast<HDC>(0)));
  CFont* font = UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(&textStyle78);
  CFont* oldFont = dc.SelectObject(font);
  CRect bounds;
  GetQDExtent(&bounds);
  bounds.DeflateRect(&contentInsets68);
  dc.DrawText(*text, text->GetLength(), &bounds, 0xd10);
  dc.SelectObject(oldFont);
  return bounds.bottom - bounds.top;
}

// FUNCTION: IMPERIALISM 0x004861f0
void TTEView::SetText(const CString& newText) {
  CString copiedText(newText);
  SetTextAndMaybeRefresh(&copiedText, 0);
}

// FUNCTION: IMPERIALISM 0x004862b0
short TTEView::GetNumberOfChars() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x004862d0
void TTEView::SetOneStyle(short start, short end, short styleMask, const TextStyle& style,
                          unsigned char refreshNow) {
  (void)start;
  (void)end;
  (void)styleMask;
  InstallTextStyle(style, refreshNow);
}

// FUNCTION: IMPERIALISM 0x00486300
void TTEView::StuffTERects(const CRect& textRect) {
  (void)textRect;
}
