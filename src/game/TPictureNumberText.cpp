#include "game/TPictureNumberText.h"
#include "game/mfc.h"

extern "C" CRuntimeClass PTR_s_TPictureNumberText_0066c3c0;

// FUNCTION: IMPERIALISM 0x005b5120
TView* __cdecl CreateTPictureNumberTextInstance(void) {
  return new TPictureNumberText();
}
// SYNTHETIC: IMPERIALISM 0x005b51c0
// TPictureNumberText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureNumberText, TNumberText)

// FUNCTION: IMPERIALISM 0x005b51e0
TPictureNumberText::TPictureNumberText() : TNumberText() {
  this->value = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x005b5210
// TPictureNumberText::`scalar deleting destructor'
TPictureNumberText::~TPictureNumberText() {}
