#include "game/TTechMgr.h"

#include "decomp_types.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"

extern "C" {
extern undefined4 DAT_0066ac88;
extern int DAT_006a601c;
}
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

// FUNCTION: IMPERIALISM 0x005af330
void TTechMgr::GenerateRandomCapabilityPrioritySlots() {
  short nCandidatePrioritySlotId;
  unsigned int dwRandomSeed;
  int nExistingSlotsToCheck;
  short* pnExistingSlotCursor;
  short* pnRangePairCursor;
  int nSelectedSlotCount;
  short* pnOutputSlotCursor;
  bool fUniqueCandidate;
  short nRangeEndGroup;
  short nRangeStartGroup;

  prioritySlots[1] = 0;
  prioritySlots[2] = 0;
  prioritySlots[0] = 0;
  if ((g_pSimMgr->field44 == 0) ||
      (dwRandomSeed = g_pGameFlowState->queueSyncDword, dwRandomSeed == 0)) {
    dwRandomSeed = reinterpret_cast<unsigned int(__cdecl*)(int)>(GetCurrentLocalEpochSecondsWithTimezoneCache)(0);
  }
  pnOutputSlotCursor = &prioritySlots[3];
  nSelectedSlotCount = 3;
  pnRangePairCursor = g_anCapabilityPriorityRangePairs;
  do {
    nRangeStartGroup = pnRangePairCursor[-1];
    nRangeEndGroup = *pnRangePairCursor;
    do {
      dwRandomSeed = dwRandomSeed * 0x15a4e35 + 1;
      fUniqueCandidate = true;
      nCandidatePrioritySlotId =
          static_cast<short>(
              static_cast<int>(
                  (dwRandomSeed >> 12 & 0x7fff) %
                  ((static_cast<int>(nRangeEndGroup * 4) - static_cast<int>(nRangeStartGroup * 4)) +
                   1)) +
              nRangeStartGroup * 4);
      *pnOutputSlotCursor = nCandidatePrioritySlotId;
      nExistingSlotsToCheck = nSelectedSlotCount;
      pnExistingSlotCursor = &prioritySlots[0];
      do {
        if (nCandidatePrioritySlotId == *pnExistingSlotCursor) {
          fUniqueCandidate = false;
        }
        nExistingSlotsToCheck--;
        pnExistingSlotCursor++;
      } while (nExistingSlotsToCheck != 0);
    } while (!fUniqueCandidate);
    pnRangePairCursor += 2;
    nSelectedSlotCount++;
    pnOutputSlotCursor++;
  } while (pnRangePairCursor < &g_anCapabilityPriorityRangePairs[52]);
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
