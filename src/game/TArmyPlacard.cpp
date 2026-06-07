#include "game/TArmyPlacard.h"

int g_pClassDescTArmyPlacard;

// FUNCTION: IMPERIALISM 0x0058be30
void* __cdecl CreateTArmyPlacardInstance(void) {
  return new TArmyPlacard();
}

// FUNCTION: IMPERIALISM 0x0058beb0
void* __cdecl GetTArmyPlacardClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyPlacard);
}

// FUNCTION: IMPERIALISM 0x0058bed0
TArmyPlacard::TArmyPlacard() : TPictureButton() {
  this->glyph90 = -1;
}

// FUNCTION: IMPERIALISM 0x0058bf00
TArmyPlacard::~TArmyPlacard() {}
