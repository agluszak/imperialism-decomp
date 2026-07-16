#include "game/TLineData.h"
// SYNTHETIC: IMPERIALISM 0x0056f360
// TLineData::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f390
// TLineData::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLineData, TObject)

// FUNCTION: IMPERIALISM 0x0056f3b0
TLineData::TLineData() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x0056f3d0
// TLineData::`scalar deleting destructor'
TLineData::~TLineData() {}

// FUNCTION: IMPERIALISM 0x0056f420
void TLineData::SetLineDataRowAndBounds(short rowArg, short colArg, int* bounds) {
  field04 = colArg;
  field08 = bounds[0];
  field0c = bounds[1];
  field06 = rowArg;
}

void TLineData::CreateLineItemView(TView* panel, int* offsetLayout) {
  (void)panel;
  (void)offsetLayout;
}

undefined TLineData::OrphanRetStub_0056f480() {
  return 0;
}
