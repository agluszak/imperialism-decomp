#include "game/trade_ui/TTradeTotalsLine.h"

#include "game/trade_ui/TTradeTotalsView.h"
// SYNTHETIC: IMPERIALISM 0x005c1870
// TTradeTotalsLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c18e0
// TTradeTotalsLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeTotalsLine, TLineData)

// FUNCTION: IMPERIALISM 0x005c1900
TTradeTotalsLine::TTradeTotalsLine() : TLineData() {}

// SYNTHETIC: IMPERIALISM 0x005c1930
// TTradeTotalsLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005c1960
TTradeTotalsLine::~TTradeTotalsLine() {}

// FUNCTION: IMPERIALISM 0x005c1980
void TTradeTotalsLine::ITradeTotalsLine(short rowArg, short colArg, int* bounds, short value) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  nationId10 = value;
}

// FUNCTION: IMPERIALISM 0x005c19c0
void TTradeTotalsLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeTotalsView* view = new TTradeTotalsView();
  view->InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, &field08, 5, 5, 0);
  view->nationSlot60 = nationId10;
}
