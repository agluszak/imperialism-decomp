#include "game/TBuildingConstructionView.h"

CRuntimeClass* TBuildingConstructionView::GetRuntimeClass() const { return 0; }

TBuildingConstructionView::~TBuildingConstructionView() {}

void TBuildingConstructionView::OpenCityViewBuildingOrderDialog(short nBuildingSlotId, int * pCityState, int nDialogContextFlags) {}

void TBuildingConstructionView::ApplyCityViewBuildingOrderDialogResult(int nDialogActionTag) {}
