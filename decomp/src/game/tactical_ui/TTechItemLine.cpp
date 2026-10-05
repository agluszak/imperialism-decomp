#include "game/tactical_ui/TTechItemLine.h"

#include "game/tactical_ui/TTechItemView.h"

IMPLEMENT_DYNCREATE(TTechItemLine, TLineData)

// FUNCTION: IMPERIALISM 0x005b1120
void TTechItemLine::ITechItemLine(short rowArg, short colArg, int* bounds, int nationSlot,
                                  int techId) {
  ILineData(rowArg, colArg, bounds);
  nationSlot10 = nationSlot;
  techId14 = techId;
}

// FUNCTION: IMPERIALISM 0x005b1160
void TTechItemLine::InstallViews(TView* panel, int* offsetLayout) {
  TTechItemView* view = new TTechItemView();
  view->ITechItemView(panel, offsetLayout, &layoutWidth, nationSlot10, techId14);
}
