#include "decomp_types.h"
#include "game/diplomacy_globals.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TNavyMgr.h"
#include "game/TSimMgr.h"
#include "game/TAssetMgr.h"
#include "game/TMacViewMgr.h"

#include "game/TLanguageMgr.h"
#include "game/THelpMgr.h"

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};
TDisplayMgr* g_pDisplayMgr = 0;
TMacViewMgr* g_pStrategicMapViewSystem = 0;
TAssetMgr* g_pUiViewManager = 0;

extern "C" {
TMinor* g_apSecondaryNationStateSlots[36] = {0};
TGreatPower* g_apNationStates[7] = {0};
void* g_apNationStates_End = reinterpret_cast<void*>(g_apNationStates + 7);
TSimMgr* g_pLocalizationTable = 0;
TLanguageMgr* g_pLanguageMgr = 0;
THelpMgr* g_pHelpMgr = 0;
TInterNationEventQueueManager* g_pInterNationEventQueueManager = 0;
TApplication* g_pGlobalUiRootController = 0;
void* g_pGameFlowState = 0;
TDiplomacyMgr* g_pDiplomacyTurnStateManager = 0;
TNavyMgr* g_pNavyOrderManager = 0;
int* g_pMapContextActionManager = 0;
char g_vtblTSortedByRelationshipList = 0;
int DAT_006a21c0 = 0;
class ImperialismApp* DAT_006a1348 = 0;
int DAT_006a1350 = 0;
void* DAT_006a1354 = 0;
}

TGreatPower* GetNationStateBySlot(short slotId) {
  return g_apNationStates[slotId];
}

short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot) {
  return nationState->GetDiplomacyExternalStateB6ByTarget(metricSlot);
}
