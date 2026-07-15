#include "game/TGWorldPartView.h"

// SYNTHETIC: IMPERIALISM 0x0045b030
// TGWorldPartView::`scalar deleting destructor'
TGWorldPartView::~TGWorldPartView() {}
// SYNTHETIC: IMPERIALISM 0x004ac7d0
// TGWorldPartView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac860
// TGWorldPartView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGWorldPartView, TView)

// FUNCTION: IMPERIALISM 0x0045b000
TGWorldPartView::TGWorldPartView() : TView() {
  sourceSurface60 = 0;
}

// FUNCTION: IMPERIALISM 0x004ac880
void TGWorldPartView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00577df0
void TGWorldPartView::SetSourceRectFromGridCell(int column, int row) {
  sourceRect64.left = column * frameWidth34;
  sourceRect64.top = row * frameHeight38;
  sourceRect64.right = (column + 1) * frameWidth34;
  sourceRect64.bottom = (row + 1) * frameHeight38;
}
