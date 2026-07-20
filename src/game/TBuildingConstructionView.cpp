#include "game/TBuildingConstructionView.h"
// SYNTHETIC: IMPERIALISM 0x004c9d70
// TBuildingConstructionView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c9e10
// TBuildingConstructionView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBuildingConstructionView, TPicture)

// FUNCTION: IMPERIALISM 0x004c9e30
TBuildingConstructionView::TBuildingConstructionView()
    : TPicture(), city90(0), productionView98(0) {}

// SYNTHETIC: IMPERIALISM 0x004c9e60
// TBuildingConstructionView::`scalar deleting destructor'
TBuildingConstructionView::~TBuildingConstructionView() {}

// FUNCTION: IMPERIALISM 0x004c9eb0
void TBuildingConstructionView::StuffValues(short buildingSlotId, TCity* city,
                                            TCityProductionView* productionView) {}

// FUNCTION: IMPERIALISM 0x004ca8f0
void TBuildingConstructionView::DoClosingAction(unsigned long dialogActionTag) {}
