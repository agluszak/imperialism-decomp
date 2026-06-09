#include "decomp_types.h"
#include "game/TDiplomacyTurnStateManager.h"
#include "game/TGreatPower.h"
#include "game/TSecondaryNationState.h"

extern "C" {
TSecondaryNationState* g_apTerrainTypeDescriptorTable[23] = {0};
TGreatPower* g_apNationStates[7] = {0};
void* g_apNationStates_End = 0;
void* g_pLocalizationTable = 0;
void* g_pInterNationEventQueueManager = 0;
void* g_pGlobalUiRootController = 0;
void* g_pGameFlowState = 0;
TDiplomacyTurnStateManager* g_pDiplomacyTurnStateManager = 0;
char g_vtblTSortedByRelationshipList = 0;
}

TGreatPower* GetNationStateBySlot(short slotId) {
  return g_apNationStates[slotId];
}

short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot) {
  return nationState->QueryNationMetricBySlot78(metricSlot);
}
