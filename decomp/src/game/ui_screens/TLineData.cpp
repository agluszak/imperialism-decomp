#include "game/ui_screens/TLineData.h"

IMPLEMENT_DYNCREATE(TLineData, TObject)

// FUNCTION: IMPERIALISM 0x0056f3b0
TLineData::TLineData() {}

// FUNCTION: IMPERIALISM 0x0056f420
void TLineData::ILineData(short rowArg, short colArg, int* bounds) {
  column = colArg;
  layoutWidth = bounds[0];
  layoutHeight = bounds[1];
  row = rowArg;
}

// FUNCTION: IMPERIALISM 0x0056f460
void TLineData::InstallViews(TView* panel, int* offsetLayout) {}

// FUNCTION: IMPERIALISM 0x0056f480
void TLineData::RemoveViews() {}
