#include "game/trade_ui/TTradeTotalsLine.h"

#include "game/trade_ui/TTradeTotalsView.h"

IMPLEMENT_DYNCREATE(TTradeTotalsLine, TLineData)

// FUNCTION: IMPERIALISM 0x005c1900
TTradeTotalsLine::TTradeTotalsLine() : TLineData() {}

// FUNCTION: IMPERIALISM 0x005c1980
void TTradeTotalsLine::ITradeTotalsLine(short rowArg, short colArg, int* bounds, short value) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  nationSlot = value;
}

// FUNCTION: IMPERIALISM 0x005c19c0
void TTradeTotalsLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeTotalsView* view = new TTradeTotalsView();
  view->InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, &layoutWidth, 5, 5,
                                                0);
  view->nationSlot = nationSlot;
}
