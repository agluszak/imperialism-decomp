#include "game/TCombatReportView.h"
#include "game/CRuntimeClass.h"

CRuntimeClass g_pClassDescTCombatReportView = {0};

// FUNCTION: IMPERIALISM 0x0058c830
void* __cdecl CreateTCombatReportViewInstance(void) {
  return new TCombatReportView();
}

// FUNCTION: IMPERIALISM 0x0058c8b0
CRuntimeClass* TCombatReportView::GetRuntimeClass() {
  return &g_pClassDescTCombatReportView;
}

// FUNCTION: IMPERIALISM 0x0058c8d0
TCombatReportView::TCombatReportView() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c900
// TCombatReportView::`scalar deleting destructor'
