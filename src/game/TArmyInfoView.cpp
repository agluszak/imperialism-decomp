#include "game/TArmyInfoView.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x663148
char g_pClassDescTArmyInfoView;

} // namespace

// FUNCTION: IMPERIALISM 0x00591500
TArmyInfoView* __cdecl CreateTArmyInfoViewInstance(void) {
  return new TArmyInfoView();
}

// FUNCTION: IMPERIALISM 0x00591580
void* __cdecl GetTArmyInfoViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyInfoView);
}

// FUNCTION: IMPERIALISM 0x005915a0
TArmyInfoView::TArmyInfoView() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x005915d0
// TArmyInfoView::`scalar deleting destructor'
