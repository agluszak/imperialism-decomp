#include "game/TAnimator.h"
// SYNTHETIC: IMPERIALISM 0x004a09f0
// TAnimator::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a0a80
// TAnimator::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAnimator, TEventHandler)

TAnimator::TAnimator() {}

// SYNTHETIC: IMPERIALISM 0x004a0ad0
// TAnimator::`scalar deleting destructor'
TAnimator::~TAnimator() {}

// FUNCTION: IMPERIALISM 0x004a0b20
void TAnimator::InitializeUiTransientObjectRegistry(int maxCount) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(0x004a0b20)(this, 0, maxCount);
}

// FUNCTION: IMPERIALISM 0x004a0c00
undefined TAnimator::OrphanCallChain_C2_I13_004a0c00() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0c30
char TAnimator::CanHandleCityDialogActionFalse(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0dc0
void TAnimator::Free() {}

// FUNCTION: IMPERIALISM 0x004a0e10
void TAnimator::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a0e50
void TAnimator::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a0fa0
void TAnimator::RemoveUiTransientRegistryObjectByTag(int tag) {
  (void)tag;
}
