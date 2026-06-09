#pragma once

#include "decomp_types.h"

struct NationState;
struct TDiplomacyTurnStateManager;

extern "C" {
class TGreatPower;
class TSecondaryNationState;

extern TSecondaryNationState* g_apTerrainTypeDescriptorTable[23];
extern TGreatPower* g_apNationStates[7];
extern void* g_apNationStates_End;
extern void* g_pLocalizationTable;
extern void* g_pInterNationEventQueueManager;
extern void* g_pGlobalUiRootController;
extern void* g_pGameFlowState;
extern TDiplomacyTurnStateManager* g_pDiplomacyTurnStateManager;
}
