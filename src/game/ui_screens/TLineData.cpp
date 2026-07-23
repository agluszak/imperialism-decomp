#include "game/ui_screens/TLineData.h"
// SYNTHETIC: IMPERIALISM 0x0056f360
// TLineData::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f390
// TLineData::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLineData, TObject)

// FUNCTION: IMPERIALISM 0x0056f3b0
TLineData::TLineData() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x0056f3d0
// TLineData::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0056f400
TLineData::~TLineData() {}

// FUNCTION: IMPERIALISM 0x0056f420
void TLineData::SetLineDataRowAndBounds(short rowArg, short colArg, int* bounds) {
  field04 = colArg;
  field08 = bounds[0];
  field0c = bounds[1];
  field06 = rowArg;
}

// FUNCTION: IMPERIALISM 0x0056f460
void TLineData::InstallViews(TView* panel, int* offsetLayout) {
  (void)panel;
  (void)offsetLayout;
}

// FUNCTION: IMPERIALISM 0x0056f480
void TLineData::RemoveViews() {}
