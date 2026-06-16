#include "decomp_types.h"
#include "game/TCountry.h"
#include "game/TDiplomacyTurnStateManager.h"
#include "game/TGreatPower.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TLocalizationRuntime.h"
#include "game/TMinor.h"

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};

extern "C" {
TMinor* g_apSecondaryNationStateSlots[36] = {0};
TGreatPower* g_apNationStates[7] = {0};
void* g_apNationStates_End = reinterpret_cast<void*>(g_apNationStates + 7);
TLocalizationRuntime* g_pLocalizationTable = 0;
TInterNationEventQueueManager* g_pInterNationEventQueueManager = 0;
void* g_pGlobalUiRootController = 0;
void* g_pGameFlowState = 0;
TDiplomacyTurnStateManager* g_pDiplomacyTurnStateManager = 0;
char g_vtblTSortedByRelationshipList = 0;
}

TGreatPower* GetNationStateBySlot(short slotId) {
  return g_apNationStates[slotId];
}

short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot) {
  return nationState->GetDiplomacyExternalStateB6ByTarget(metricSlot);
}
