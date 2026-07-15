#include "game/TTechMgr.h"

#include "decomp_types.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"

#include <string.h>

#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

undefined4 RecomputeGlobalCapabilityAverages(void);
undefined4 GetCurrentLocalEpochSecondsWithTimezoneCache(void);

TTechMgr* g_pCityOrderCapabilityState = 0;
// SYNTHETIC: IMPERIALISM 0x005aef30
// TTechMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005aef60
// TTechMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechMgr, TObject)

TTechMgr::TTechMgr() {}

TTechMgr::~TTechMgr() {}

// FUNCTION: IMPERIALISM 0x005aef80
void TTechMgr::ConstructCityOrderCapabilityStateVtable(void) {}

// SYNTHETIC: IMPERIALISM 0x005aefa0
// TTechMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005aeff0
void TTechMgr::InitializeCityOrderCapabilityStateDefaults(void) {
  // Scalar capability defaults (0x180..0x1d6).
  perTechUnlockFlag180[0] = 1;
  perTechUnlockFlag180[1] = 1;
  perTechUnlockFlag180[2] = 1;
  memset(&perTechUnlockFlag180[3], 0, sizeof(perTechUnlockFlag180) - 3);
  hasProductionOrder193 = 0;
  memset(pad194, 0, sizeof(pad194));
  initFlags19d[0] = 1;
  initFlags19d[1] = 1;
  initFlags19d[2] = 1;
  initFlags19d[3] = 1;
  initFlag1a1 = 1;
  capabilityFlag1a2 = 0;
  capabilityFlag1a3 = 0;
  capabilityFlag1a4 = 0;
  shipCapabilityFlag1a5 = 0;
  capabilityFlag1a6 = 0;
  capabilityFlag1a7 = 0;
  shipCapabilityFlag1a8 = 0;
  capabilityFlag1a9 = 0;
  capabilityFlag1aa = 0;
  initFlags1ab[0] = 1;
  initFlags1ab[1] = 1;
  initFlags1ab[2] = 1;
  initFlags1ab[3] = 1;
  initFlags1af[0] = 1;
  initFlags1af[1] = 1;
  initFlags1af[2] = 1;
  initFlags1af[3] = 1;
  flag1c3 = 1;
  memset(initFlags1c9, 0, sizeof(initFlags1c9));
  initFlags1c9[0] = 1;
  initFlags1c9[1] = 1;
  initFlags1c9[2] = 1;
  initFlags1c9[4] = 1;
  initFlags1c9[7] = 1;
  techSelectorShort1d2 = 3;
  activeZoneIndex1d4 = 4;

  // Per-nation capability tables (7 nations each).
  int j;
  for (int n = 0; n < 7; ++n) {
    // capabilityValueByNationAndResource: clear the row, set the default-unlocked columns.
    memset(capabilityValueByNationAndResource[n], 0, sizeof(capabilityValueByNationAndResource[n]));
    capabilityValueByNationAndResource[n][3] = 1;
    capabilityValueByNationAndResource[n][4] = 1;
    capabilityValueByNationAndResource[n][0x11] = 1;
    capabilityValueByNationAndResource[n][0x12] = 1;
    capabilityValueByNationAndResource[n][0x15] = 1;
    capabilityValueByNationAndResource[n][0x16] = 1;

    // nationCapRows: slots[0..7] = 0..7, slots[8] = 0x18, slots[9] = 0x1b.
    for (j = 0; j < 8; ++j) {
      nationCapRows1e8[n].slots[j] = static_cast<short>(j);
    }
    nationCapRows1e8[n].slots[8] = 0x18;
    nationCapRows1e8[n].slots[9] = 0x1b;

    // orderCapRows: first three bytes = 2, rest cleared.
    memset(&orderCapRows277[n], 0, sizeof(OrderCapRow));
    orderCapRows277[n].initReadyFlag[0] = 2;
    orderCapRows277[n].initReadyFlag[1] = 2;
    orderCapRows277[n].initReadyFlag[2] = 2;

    // capRowsB: first five bytes = 1, rest cleared.
    memset(&capRowsB333[n], 0, sizeof(CapRowB));
    for (j = 0; j < 5; ++j) {
      capRowsB333[n].flags[j] = 1;
    }

    // militaryCapRows: initFlags[0..7] = 1 plus the two tail flags; readers' recruit/elite
    // flags stay cleared.
    memset(&militaryCapRows39d[n], 0, sizeof(MilitaryCapRow));
    for (j = 0; j < 8; ++j) {
      militaryCapRows39d[n].initFlags[j] = 1;
    }
    militaryCapRows39d[n].initFlag18 = 1;
    militaryCapRows39d[n].initFlag1b = 1;

    // capRowsD: flags {0,1,2,4,7} = 1.
    memset(&capRowsD467[n], 0, sizeof(CapRowD));
    capRowsD467[n].flags[0] = 1;
    capRowsD467[n].flags[1] = 1;
    capRowsD467[n].flags[2] = 1;
    capRowsD467[n].flags[4] = 1;
    capRowsD467[n].flags[7] = 1;

    // capRowsE: cleared.
    memset(&capRowsE4a6[n], 0, sizeof(CapRowE));
  }

  marker262 = 2;
  ruleTablePointer264 = DAT_0066ac88;
  RecomputeGlobalCapabilityAverages();
}

// Fills the capability-priority selection slots with 26 unique random slot ids, one per
// (start, end) range pair. The LCG is seeded from the game-flow queue sync dword when session
// state is active, otherwise from the wall clock. Each candidate is retried until it is unique
// among the already-selected slots.
// FUNCTION: IMPERIALISM 0x005af330
void TTechMgr::GenerateRandomCapabilityPrioritySlots() {
  prioritySlots04[1] = 0;
  prioritySlots04[2] = 0;
  prioritySlots04[0] = 0;

  unsigned int seed;
  if (g_pSimMgr->field44 == 0 ||
      (seed = static_cast<unsigned int>(g_pGameFlowState->queueSyncDword)) == 0) {
    // Genuine __cdecl free function declared (void); the guardrail-sanctioned arg-adjust cast
    // pushes the ignored 0 argument the original passes.
    seed = reinterpret_cast<unsigned int(__cdecl*)(int)>(
        GetCurrentLocalEpochSecondsWithTimezoneCache)(0);
  }

  short* pnOutputSlotCursor = &prioritySlots04[3];
  int nSelectedSlotCount = 3;
  // Pair i is (cursor[-1], cursor[0]); the reccmp symbol anchors pair 0's END, so pair 0's
  // START is read one short before the array.
  for (short* pnRangePairCursor = &g_anCapabilityPriorityRangePairs[0];
       pnRangePairCursor < &g_anCapabilityPriorityRangePairs[52]; pnRangePairCursor += 2) {
    short nRangeStartGroup = pnRangePairCursor[-1];
    short nRangeEndGroup = *pnRangePairCursor;
    int nRangeSpan =
        (static_cast<short>(nRangeEndGroup << 2) - static_cast<short>(nRangeStartGroup * 4)) + 1;
    bool fUniqueCandidate;
    do {
      seed = seed * 0x15a4e35 + 1;
      fUniqueCandidate = true;
      short nCandidatePrioritySlotId =
          static_cast<short>(static_cast<int>((seed >> 0xc) & 0x7fff) % nRangeSpan) +
          static_cast<short>(nRangeStartGroup * 4);
      *pnOutputSlotCursor = nCandidatePrioritySlotId;
      short* pnExistingSlotCursor = &prioritySlots04[0];
      for (int nRemaining = nSelectedSlotCount; nRemaining != 0; nRemaining--) {
        if (nCandidatePrioritySlotId == *pnExistingSlotCursor) {
          fUniqueCandidate = false;
        }
        pnExistingSlotCursor++;
      }
    } while (!fUniqueCandidate);
    nSelectedSlotCount++;
    pnOutputSlotCursor++;
  }
  RecomputeGlobalCapabilityAverages();
}

// FUNCTION: IMPERIALISM 0x005af460
void TTechMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005af710
void TTechMgr::WriteTo(TStream* stream) {
  (void)stream;
}

// Applies a technology-unlock id to the city-order capability state: records the active tech
// marker, sets the per-tech unlock flag, then toggles the dependent capability flags/selector
// shorts for the milestone techs. Ids 0x0b/0x16 swap the rule-table pointer at +0x264.
// FUNCTION: IMPERIALISM 0x005afba0
void TTechMgr::ApplyCityOrderCapabilityUnlockByTechId(int nTechId) {
  marker262 = static_cast<short>(nTechId);
  perTechUnlockFlag180[nTechId] = 1;
  switch (nTechId) {
  case 9:
    capabilityFlag1a4 = 1;
    techSelectorShort1d2 = 7;
    capabilityFlag1a2 = 1;
    return;
  case 4:
    capabilityFlag1a3 = 1;
    return;
  case 0xf:
    shipCapabilityFlag1a5 = 1;
    activeZoneIndex1d4 = 8;
    return;
  case 0xb:
    ruleTablePointer264 = DAT_0066ac8c;
    return;
  case 0x15:
    capabilityFlag1a6 = 1;
    activeZoneIndex1d4 = 9;
    return;
  case 0x18:
    shipCapabilityFlag1a8 = 1;
    techSelectorShort1d2 = 0xb;
    capabilityFlag1a7 = 1;
    return;
  case 0x1b:
    capabilityFlag1a9 = 1;
    activeZoneIndex1d4 = 0xc;
    capabilityFlag1aa = 1;
    techSelectorShort1d2 = 0xd;
    return;
  case 0x16:
    ruleTablePointer264 = DAT_0066ac90;
    break;
  }
}

// Whether both capability flags of a tech prerequisite pair are completed (== 2) for a
// nation: the pair's two in-record byte offsets come from
// g_awTechPrereqCapabilityFieldOffsetPairs_0066ac10[prereqPairIndex], read against the
// nation's orderCapRows277 row.
// FUNCTION: IMPERIALISM 0x005b0a20
unsigned char TTechMgr::AreTechItemPrerequisitePairCompleted(int prereqPairIndex, int nationIndex) {
  // Each capability flag is read as a "column": shift the object base by the flag's
  // in-record byte offset, then index orderCapRows277 by nation. Reinterpreting the
  // shifted base as a TTechMgr keeps (this + offset) as the record base and lets the
  // 0x268 member displacement + nation*0x1d stride ride the addressing mode, matching the
  // original's [this + fieldOffset + nation*0x1d + 0x268] grouping. The record's offset-0
  // byte then IS the shifted field.
  const short* offsets = g_awTechPrereqCapabilityFieldOffsetPairs_0066ac10[prereqPairIndex];
  if (reinterpret_cast<TTechMgr*>(reinterpret_cast<unsigned char*>(this) + offsets[0])
              ->orderCapRows277[nationIndex]
              .initReadyFlag[0] == 2 &&
      reinterpret_cast<TTechMgr*>(reinterpret_cast<unsigned char*>(this) + offsets[1])
              ->orderCapRows277[nationIndex]
              .initReadyFlag[0] == 2) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b0c70
void TTechMgr::SetCityOrderCapabilityTierScaledValueByIndex(int index, int value) {
  prioritySlots04[index] = static_cast<short>(value * 4);
}

// Returns a nation's maximum fortification level (1..3): level 3 if the advanced-fort flag is
// set, level 2 if the intermediate flag is set, else level 1. The advanced flag lives in the
// nation's own orderCapRows277 row; the intermediate flag lives 4 bytes before it, i.e. in the
// previous nation's row (the same previous-row / orderCapRows277[-1] striding documented on
// OrderCapRow for nation 0).
// FUNCTION: IMPERIALISM 0x005b0ca0
int TTechMgr::GetNationFortLevelCap(int nNationId) {
  if (orderCapRows277[nNationId].advancedFortFlag != 0) {
    return 3;
  }
  return (orderCapRows277[nNationId].intermediateFortFlag != 0) + 1;
}
