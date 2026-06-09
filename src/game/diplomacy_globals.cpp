#include "decomp_types.h"
#include "game/NationState.h"
#include "game/TDiplomacyTurnStateManager.h"

extern "C" {
NationState* g_apTerrainTypeDescriptorTable[23] = {0};
NationState* g_apNationStates[7] = {0};
void* g_apNationStates_End = 0;
void* g_pLocalizationTable = 0;
void* g_pInterNationEventQueueManager = 0;
void* g_pGlobalUiRootController = 0;
void* g_pGameFlowState = 0;
TDiplomacyTurnStateManager* g_pDiplomacyTurnStateManager = 0;
char g_vtblTSortedByRelationshipList = 0;
}
