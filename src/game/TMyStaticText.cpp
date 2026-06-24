#include "game/TMyStaticText.h"
#include "game/TStaticText.h"

// FUNCTION: IMPERIALISM 0x005b5400
CRuntimeClass* TMyStaticText::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005b5450
// TMyStaticText::`scalar deleting destructor'
TMyStaticText::~TMyStaticText() {}

// FUNCTION: IMPERIALISM 0x005b5420
TMyStaticText* TMyStaticText::ConstructUiTextResourceEntry_Vtbl0066cbc8() {
  TStaticText::TStaticText();
  return this;
}
