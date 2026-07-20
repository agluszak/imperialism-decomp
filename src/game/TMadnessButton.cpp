#include "game/TMadnessButton.h"

// SYNTHETIC: IMPERIALISM 0x0043d720
// TMadnessButton::`scalar deleting destructor'
TMadnessButton::~TMadnessButton() {}
// SYNTHETIC: IMPERIALISM 0x0054ea30
// TMadnessButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054ead0
// TMadnessButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMadnessButton, TCzechBox)

TMadnessButton::TMadnessButton() {}

// FUNCTION: IMPERIALISM 0x0054eaf0
void TMadnessButton::DoPostCreate(int arg) {
  TCzechBox::DoPostCreate(arg);
  initialPictureId = glyphBase84;
  OrphanCallChain_C1_I10_00571e00(1, 0);
}

// FUNCTION: IMPERIALISM 0x0054eb30
undefined TMadnessButton::OrphanCallChain_C4_I45_00571d40(char param_1) {
  return 0;
}
