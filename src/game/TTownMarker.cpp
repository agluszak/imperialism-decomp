#include "game/TTownMarker.h"

#include "game/TLocalizationRuntime.h"
#include <string.h>

#include "game/diplomacy_globals.h"
#include "game/CRuntimeClass.h"

extern "C" CRuntimeClass PTR_s_TTownMarker_0066d780;

// MFC-style GetRuntimeClass (slot 0): returns the class descriptor that precedes
// the vtable at 0x0066d7c8.
// FUNCTION: IMPERIALISM 0x005b6c40
CRuntimeClass* TTownMarker::GetRuntimeClass() const {
  return &PTR_s_TTownMarker_0066d780;
}

// Bare vptr-write constructor; all field state comes from InitializeTownMarker.
// FUNCTION: IMPERIALISM 0x005b6c60
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
  this->createdTurnTick1a = g_pLocalizationTable->GetTurnTickSlot3C();
  this->transportLinkedFlag4c = 0;
  memset(this->payload1e, 0, sizeof(this->payload1e));
}
#pragma optimize("", on)

extern undefined4 HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(void);

// FUNCTION: IMPERIALISM 0x005b7830
char TTownMarker::IsTransportLinkedAndEnabled(void) {
  if (this->enabledFlag4d == 0) {
    return 0;
  }
  char(__cdecl * hasReachableSeaTile)(short) = reinterpret_cast<char(__cdecl*)(short)>(
      HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask);
  if (hasReachableSeaTile(this->regionId14) == 0) {
    return 0;
  }
  return 1;
}
