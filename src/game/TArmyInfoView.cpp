#include "game/TArmyInfoView.h"
#include "game/mfc.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663148
}

// FUNCTION: IMPERIALISM 0x00591500
TArmyInfoView* __cdecl CreateTArmyInfoViewInstance(void) {
  return new TArmyInfoView();
}
IMPLEMENT_DYNCREATE(TArmyInfoView, TPicture)

// FUNCTION: IMPERIALISM 0x005915a0
TArmyInfoView::TArmyInfoView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005915d0
// TArmyInfoView::`scalar deleting destructor'
TArmyInfoView::~TArmyInfoView() {}

// FUNCTION: IMPERIALISM 0x00591620
bool TArmyInfoView::IsSelected(short value, bool refreshNow) {
  (void)value;
  (void)refreshNow;
  return false;
}
