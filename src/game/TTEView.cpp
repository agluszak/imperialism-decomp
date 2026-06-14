#include "game/TTEView.h"

// FUNCTION: IMPERIALISM 0x0061f342
void TTEView::DeflateRect(RECT* margins) {
  RECT* rect = reinterpret_cast<RECT*>(this);
  rect->left += margins->left;
  rect->top += margins->top;
  rect->right -= margins->right;
  rect->bottom -= margins->bottom;
}
