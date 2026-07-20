#include "game/TUniversityView.h"
// SYNTHETIC: IMPERIALISM 0x004caba0
// TUniversityView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cac40
// TUniversityView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUniversityView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cac60
TUniversityView::TUniversityView() {}

// SYNTHETIC: IMPERIALISM 0x004cac90
// TUniversityView::`scalar deleting destructor'
TUniversityView::~TUniversityView() {}

// FUNCTION: IMPERIALISM 0x004cace0
undefined TUniversityView::OrphanRetStub_004c6fd0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cb320
void TUniversityView::SelectUniversityRecruitmentEntry(short nRecruitmentEntryIndex) {}

// FUNCTION: IMPERIALISM 0x004cb8a0
void TUniversityView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short index = static_cast<short>(sourceHandler->controlTag) - 0x7630; // 'rec0'-'rec8' low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentIndexA4 = index;
      SelectUniversityRecruitmentEntry(index);
    }
  } else if (commandId == 0xa) {
    TView* ownerView = static_cast<TView*>(sourceHandler)->ownerContext;
    short index = static_cast<short>(ownerView->controlTag) - 0x7530; // low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentIndexA4 = index;
      SelectUniversityRecruitmentEntry(index);

      // The original then resolves the 'sele' control (AssertValid, a slot-0x1c8 call with
      // tag 'civ0'+index -- same unresolved receiver class as
      // TShipyardView::OrphanRetStub_004c6fd0's 'sele' tail) and dispatches to the real
      // receiver at field94[index+0x22] (field94's pointee class is unresolved -- see
      // RefreshCityViewProductionDetails, 0x4cfbd0, 1748 bytes) which drives a 'num0'+index
      // control's embedded 'numb' widget and a final invalidate/refresh sequence -- not yet
      // ported.
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cbb20
undefined TUniversityView::OrphanRetStub_004c6fb0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cbf30
void TUniversityView::Free() {}

// FUNCTION: IMPERIALISM 0x004cbf70
void TUniversityView::ApplyRectSlot110(RECT* rectBuffer) {}
