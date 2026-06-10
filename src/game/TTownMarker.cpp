#include "game/TTownMarker.h"

#include "game/TLocalizationRuntime.h"
#include <string.h>

#include "game/diplomacy_globals.h"

// FUNCTION: IMPERIALISM 0x005b6c60
// Bare vptr-write constructor; all field state comes from InitializeTownMarker.
TTownMarker::TTownMarker() {}

// FUNCTION: IMPERIALISM 0x005b6cd0
#pragma optimize("y", on)
void TTownMarker::InitializeTownMarker(const char* markerName, short regionId, char enabledFlag,
                                       short ownerNation) {
  strcpy(this->name, markerName);
  this->ownerNation1c = ownerNation;
  this->regionId14 = regionId;
  this->enabledFlag4d = enabledFlag;
  this->activeFlag4f = enabledFlag == 0;
  this->flags16[0] = 0;
  this->flags16[1] = 0;
  this->flags16[2] = 0;
  this->flags16[3] = 0;
  this->createdTurnTick1a =
      g_pLocalizationTable->GetTurnTickSlot3C();
  this->transportLinkedFlag4c = 0;
  memset(this->payload1e, 0, sizeof(this->payload1e));
}
#pragma optimize("", on)
