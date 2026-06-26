#pragma once

#include "decomp_types.h"

#include "game/TDealList.h"
#include "game/TCountry.h"

struct NationState;
class TDiplomacyMgr;
class TNavyMgr;
class TSimMgr;
class TAssetMgr;
class TInterNationEventQueueManager;

class TLanguageMgr;

extern "C" {
class TGreatPower;
class TMinor;
class TApplication;
// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];
// Parallel to g_apMinorNationCapabilityObjects[16] — aux runtime terrain rows.
extern TMinor* g_apNationAuxRuntimeStateSlots[16];
extern TMinor* g_apMinorNationCapabilityObjects[16];
extern TGreatPower* g_apNationStates[7];
extern void* g_apNationStates_End;
extern TSimMgr* g_pLocalizationTable;
extern TLanguageMgr* g_pLanguageMgr;
extern TAssetMgr* g_pUiViewManager;
extern TInterNationEventQueueManager* g_pInterNationEventQueueManager;
extern TApplication* g_pGlobalUiRootController;
extern void* g_pGameFlowState;
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
extern TNavyMgr* g_pNavyOrderManager;
extern int* g_pMapContextActionManager;
extern int DAT_006a21c0;
extern class ImperialismApp* DAT_006a1348;
extern int DAT_006a1350;
extern void* DAT_006a1354;
}
