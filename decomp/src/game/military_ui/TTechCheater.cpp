#include "game/military_ui/TTechCheater.h"

// FUNCTION: IMPERIALISM 0x004b1920
TTechCheater::~TTechCheater() {}

IMPLEMENT_DYNCREATE(TTechCheater, TCheater)

// FUNCTION: IMPERIALISM 0x004b1960
void TTechCheater::ConstructTTechCheaterBaseState(TView* panel) {
  ConstructTCheaterBaseState(panel, 0x2727);
}

// FUNCTION: IMPERIALISM 0x004b1990
void TTechCheater::ApplyCheats() {}
