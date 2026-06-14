#include "game/TArmyInfoView.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663148
CRuntimeClass g_pClassDescTArmyInfoView = {0};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00591500
TArmyInfoView* __cdecl CreateTArmyInfoViewInstance(void) {
  return new TArmyInfoView();
}

// FUNCTION: IMPERIALISM 0x00591580
CRuntimeClass* TArmyInfoView::GetRuntimeClass() {
  return &g_pClassDescTArmyInfoView;
}

// FUNCTION: IMPERIALISM 0x005915a0
TArmyInfoView::TArmyInfoView() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x005915d0
// TArmyInfoView::`scalar deleting destructor'
