#include "game/military_ui/TMiniCivLine.h"

#include "game/military_ui/TMiniCivView.h"

IMPLEMENT_DYNCREATE(TMiniCivLine, TLineData)

// FUNCTION: IMPERIALISM 0x004ab700
void TMiniCivLine::IMiniCivLine(short rowArg, short colArg, int* bounds, TCivUnit* item) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  civUnit10 = item;
}

// FUNCTION: IMPERIALISM 0x004ab740
void TMiniCivLine::InstallViews(TView* panel, int* offsetLayout) {
  TMiniCivView* view = new TMiniCivView();
  view->InitializeForCivilianUnit(panel, offsetLayout, &layoutWidth, civUnit10);
}
