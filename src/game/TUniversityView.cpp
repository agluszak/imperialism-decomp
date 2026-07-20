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
  // The original dispatches on field94's real receiver class via a lookup keyed by
  // field94+0xe4+idx*4 -- its only assignment site, RefreshCityViewProductionDetails
  // (0x4cfbd0, 1748 bytes), is itself unported, so the receiver class is unresolved here
  // too -- not yet ported.
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
