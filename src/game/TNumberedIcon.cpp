#include "game/TNumberedIcon.h"
// SYNTHETIC: IMPERIALISM 0x005072e0
// TNumberedIcon::CreateObject

// SYNTHETIC: IMPERIALISM 0x00507380
// TNumberedIcon::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberedIcon, TMegaPicture)

// FUNCTION: IMPERIALISM 0x005073a0
TNumberedIcon::TNumberedIcon() : TMegaPicture(), fieldAc(0) {}

// SYNTHETIC: IMPERIALISM 0x005073d0
// TNumberedIcon::`scalar deleting destructor'
TNumberedIcon::~TNumberedIcon() {}

// FUNCTION: IMPERIALISM 0x005074e0
void TNumberedIcon::NoOpUiLifecycleHook(int arg) {
  TMegaPicture::NoOpUiLifecycleHook(arg);
  AssignFlags98AndMaybeRefresh(5, 1);
  NumberedIconSlot77();
  // The original then, when fieldAc is set, builds a RECT from frameWidth34/frameHeight38
  // (each offset by -0x10 for two of the four fields; the remaining two aren't resolved)
  // and calls fieldAc->ApplyBounds(&rect, 1) -- left unmodeled pending the full rect shape.
}

// FUNCTION: IMPERIALISM 0x00507570
undefined TNumberedIcon::NumberedIconSlot77() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005076d0
undefined TNumberedIcon::OrphanCallChain_C1_I10_005076d0(short param_1) {
  return 0;
}
