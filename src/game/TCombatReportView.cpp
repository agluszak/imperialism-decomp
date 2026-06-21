#include "game/TCombatReportView.h"
#include "game/mfc.h"
#include "game/TControl.h"

CRuntimeClass g_pClassDescTCombatReportView = {nullptr, 0, 0, nullptr, nullptr};



// FUNCTION: IMPERIALISM 0x0058c830
void* __cdecl CreateTCombatReportViewInstance(void) {
  return new TCombatReportView();
}



// FUNCTION: IMPERIALISM 0x0058c8b0
CRuntimeClass* TCombatReportView::GetRuntimeClass() const {
  return &g_pClassDescTCombatReportView;
}



// FUNCTION: IMPERIALISM 0x0058c8d0
TCombatReportView::TCombatReportView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.



// SYNTHETIC: IMPERIALISM 0x0058c900
// TCombatReportView::`scalar deleting destructor'


// FUNCTION: IMPERIALISM 0x0058c950
bool TCombatReportView::IsSelected(short value, bool refreshNow) {
  (void)value;
  (void)refreshNow;
  return false;
}



// FUNCTION: IMPERIALISM 0x0058d2b0
void TCombatReportView::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
}



// FUNCTION: IMPERIALISM 0x0058d950
void TCombatReportView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::HandleEvent(commandId, sourceHandler, event);
}


TCombatReportView::~TCombatReportView() {}
