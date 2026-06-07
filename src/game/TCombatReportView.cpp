#include "game/TCombatReportView.h"

int g_pClassDescTCombatReportView;

// FUNCTION: IMPERIALISM 0x0058c830
void* __cdecl CreateTCombatReportViewInstance(void) {
  return new TCombatReportView();
}

// FUNCTION: IMPERIALISM 0x0058c8b0
void* __cdecl GetTCombatReportViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCombatReportView);
}

// FUNCTION: IMPERIALISM 0x0058c8d0
TCombatReportView::TCombatReportView() : TPictureButton() {
}

// FUNCTION: IMPERIALISM 0x0058c900
TCombatReportView::~TCombatReportView() {
}
