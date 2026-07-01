#include "game/TTEView.h"

// SYNTHETIC: IMPERIALISM 0x0045ad70
// TTEView::`scalar deleting destructor'
TTEView::~TTEView() {}
// SYNTHETIC: IMPERIALISM 0x00485fb0
// TTEView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486030
// TTEView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTEView, TStaticText)

TTEView::TTEView() {}

// FUNCTION: IMPERIALISM 0x0061f342
void TTEView::DeflateRect(RECT* margins) {
  RECT* rect = reinterpret_cast<RECT*>(this);
  rect->left += margins->left;
  rect->top += margins->top;
  rect->right -= margins->right;
  rect->bottom -= margins->bottom;
}

