#include "game/TTechMgr.h"

#include "decomp_types.h"
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
  int self = reinterpret_cast<int>(this);
  int iVar1;
  undefined2* puVar2;
  undefined2* puVar3;
  undefined* puVar4;
  undefined4* puVar5;
  undefined4* puVar6;
  undefined4* local_10;
  undefined4* local_c;
  undefined4* local_8;
  undefined* local_4;

  *(undefined*)(self + 0x180) = 1;
  *(undefined*)(self + 0x181) = 1;
  *(undefined*)(self + 0x182) = 1;
  puVar5 = reinterpret_cast<undefined4*>(self + 0x183);
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2*)puVar5 = 0;
  *(undefined4*)(self + 0x19d) = 0x1010101;
  *(undefined*)(self + 0x1a1) = 1;
  *(undefined4*)(self + 0x1a2) = 0;
  *(undefined4*)(self + 0x1a6) = 0;
  *(undefined*)(self + 0x1aa) = 0;
  *(undefined2*)(self + 0x1d2) = 3;
  *(undefined2*)(self + 0x1d4) = 4;
  *(undefined4*)(self + 0x1c9) = 0;
  puVar4 = reinterpret_cast<undefined*>(self + 0x269);
  local_4 = reinterpret_cast<undefined*>(0x7);
  *(undefined4*)(self + 0x1cd) = 0;
  *(undefined*)(self + 0x1d1) = 0;
  *(undefined*)(self + 0x1c9) = 1;
  local_8 = reinterpret_cast<undefined4*>(self + 0x395);
  *(undefined*)(self + 0x1ca) = 1;
  *(undefined*)(self + 0x1cd) = 1;
  *(undefined*)(self + 0x1cb) = 1;
  *(undefined*)(self + 0x1d0) = 1;
  *(undefined4*)(self + 0x1ab) = 0x1010101;
  local_c = reinterpret_cast<undefined4*>(self + 0x333);
  local_10 = reinterpret_cast<undefined4*>(self + 0x4a6);
  *(undefined4*)(self + 0x1af) = 0x1010101;
  *(undefined*)(self + 0x1c3) = 1;
  *(undefined2*)(self + 0x262) = 2;
  puVar5 = reinterpret_cast<undefined4*>(self + 0x467);
  do {
    puVar4[-1] = 2;
    *puVar4 = 2;
    puVar4[1] = 2;
    puVar6 = reinterpret_cast<undefined4*>(puVar4 + 2);
    for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2*)puVar6 = 0;
    puVar4 = puVar4 + 0x1d;
    puVar6 = local_10;
    for (iVar1 = 0xe; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2*)puVar6 = 0;
    *local_c = 0;
    local_c[1] = 0;
    local_c[2] = 0;
    *(undefined2*)(local_c + 3) = 0;
    puVar6 = local_8;
    for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2*)puVar6 = 0;
    *puVar5 = 0;
    local_8 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_8) + 0x1e);
    puVar5[1] = 0;
    *(undefined*)(puVar5 + 2) = 0;
    *(undefined*)puVar5 = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 1) = 1;
    local_c = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_c) + 0xe);
    *(undefined*)(puVar5 + 1) = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 2) = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 7) = 1;
    local_10 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_10) + 0x3a);
    local_4 = reinterpret_cast<undefined*>(reinterpret_cast<char*>(local_4) + -1);
    puVar5 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(puVar5) + 9);
  } while (local_4 != reinterpret_cast<undefined*>(0));
  local_10 = reinterpret_cast<undefined4*>(self + 0x338);
  local_8 = reinterpret_cast<undefined4*>(self + 0x1e6);
  local_4 = reinterpret_cast<undefined*>(self + 0x3ad);
  puVar5 = reinterpret_cast<undefined4*>(self + 0x467);
  puVar3 = reinterpret_cast<undefined2*>(self + 0x62);
  local_c = reinterpret_cast<undefined4*>(0x7);
  do {
    puVar6 = reinterpret_cast<undefined4*>(puVar3 + -0x12);
    for (iVar1 = 0xb; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2*)puVar6 = 0;
    *puVar3 = 1;
    puVar3[-1] = 1;
    puVar3[3] = 1;
    puVar3[-0xe] = 1;
    puVar3[-0xf] = 1;
    puVar3[4] = 1;
    *puVar5 = 0;
    puVar5[1] = 0;
    *(undefined*)(puVar5 + 2) = 0;
    *(undefined*)puVar5 = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 1) = 1;
    *(undefined*)(puVar5 + 1) = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 2) = 1;
    *(undefined*)(reinterpret_cast<char*>(puVar5) + 7) = 1;
    *(undefined4*)(local_4 + -0x18) = 0x1010101;
    *(undefined4*)(local_4 + -0x14) = 0x1010101;
    *local_4 = 1;
    local_4[3] = 1;
    *(undefined4*)(reinterpret_cast<char*>(local_10) + -5) = 0x1010101;
    *(undefined*)(reinterpret_cast<char*>(local_10) + -1) = 1;
    *local_10 = 0;
    local_10[1] = 0;
    *(undefined*)(local_10 + 2) = 0;
    iVar1 = 0;
    puVar2 = reinterpret_cast<undefined2*>(reinterpret_cast<char*>(local_8) + -0x10);
    do {
      *puVar2 = static_cast<short>(iVar1);
      iVar1 = iVar1 + 1;
      puVar2 = puVar2 + 1;
    } while (iVar1 < 8);
    local_4 = local_4 + 0x1e;
    *(undefined2*)local_8 = 0x18;
    *(undefined2*)(reinterpret_cast<char*>(local_8) + 2) = 0x1b;
    local_8 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_8) + 0x14);
    puVar3 = puVar3 + 0x17;
    puVar5 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(puVar5) + 9);
    local_10 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_10) + 0xe);
    local_c = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(local_c) + -1);
  } while (local_c != reinterpret_cast<undefined4*>(0));
  *(undefined4*)(self + 0x264) = DAT_0066ac88;
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
  // 0x262 lands in nationCapRows1e8[6].caps[1]; 0x264 (the rule-table pointer) overlays the
  // 4 bytes at caps[2..3] of the same row.
  nationCapRows1e8[6].caps[1] = static_cast<short>(nTechId);
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
    nationCapRows1e8[6].techState.ruleTablePointer264 = DAT_0066ac8c;
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
    nationCapRows1e8[6].techState.ruleTablePointer264 = DAT_0066ac90;
    break;
  }
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
  return (orderCapRows277[nNationId - 1].intermediateFortFlag != 0) + 1;
}
