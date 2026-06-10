#pragma once

#include "decomp_types.h"

struct NationState;
struct TDiplomacyTurnStateManager;

extern "C" {
class TGreatPower;
class TMinor;

extern TMinor* g_apTerrainTypeDescriptorTable[23];
// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];
// Parallel to g_apMinorNationCapabilityObjects[16] — aux runtime terrain rows.
extern TMinor* g_apNationAuxRuntimeStateSlots[16];
extern TGreatPower* g_apNationStates[7];
extern void* g_apNationStates_End;
extern void* g_pLocalizationTable;
extern void* g_pInterNationEventQueueManager;
extern void* g_pGlobalUiRootController;
extern void* g_pGameFlowState;
extern TDiplomacyTurnStateManager* g_pDiplomacyTurnStateManager;
}
