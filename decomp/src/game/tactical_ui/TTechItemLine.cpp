#include "game/tactical_ui/TTechItemLine.h"

#include "game/tactical_ui/TTechItemView.h"

IMPLEMENT_DYNCREATE(TTechItemLine, TLineData)

// FUNCTION: IMPERIALISM 0x005b1120
void TTechItemLine::ITechItemLine(short rowArg, short colArg, int* bounds, int nationSlot,
                                  int techId) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  nationSlot10 = nationSlot;
  techId14 = techId;
}

// Virtual line factory: builds this tech line's TTechItemView, sized by the inherited
// layoutWidth/layoutHeight bound pair and parameterized by this line's nation slot and tech id.
// FUNCTION: IMPERIALISM 0x005b1160
void TTechItemLine::InstallViews(TView* panel, int* offsetLayout) {
  TTechItemView* view = new TTechItemView();
  view->ITechItemView(panel, offsetLayout, &layoutWidth, nationSlot10, techId14);
}
