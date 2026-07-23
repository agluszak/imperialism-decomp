#include <time.h>

#include "game/TTechMgr.h"

#include "decomp_types.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNewsMgr.h"
#include "game/global_data_tables.h"

#include <string.h>

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/TAdmiral.h"
#include "game/TCity.h"
#include "game/TCountry.h"
#include "game/TMacViewMgr.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TShip.h"
#include "game/TStream.h"
#include "game/navy_order.h"
#include "game/nation_stream_serialization.h"
#include "game/TTaskForce.h"
#include "game/TUnitOrder.h"
#include "game/TViewMgr.h"
#include "game/mapped_flavor_text.h"


TTechMgr* g_pCityOrderCapabilityState = 0;

// FUNCTION: IMPERIALISM 0x005572d0
short GetEnabledIndustryCapabilitySlotByClass(short classId) {
  unsigned char* flagRegion = reinterpret_cast<unsigned char*>(g_pCityOrderCapabilityState) + 0x19d;
  short slot = 13;
  const IndustryCapabilityClassSlotEntry* entry = &g_aIndustryCapabilityClassSlotTable[13];
  while (entry->classId != classId || flagRegion[slot] == 0) {
    entry--;
    slot--;
    if (entry == g_aIndustryCapabilityClassSlotTable) {
      return 0;
    }
  }
  return slot;
}
// SYNTHETIC: IMPERIALISM 0x005aef30
// TTechMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005aef60
// TTechMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechMgr, TObject)

TTechMgr::~TTechMgr() {}

// FUNCTION: IMPERIALISM 0x005aef80
TTechMgr::TTechMgr() {}

// SYNTHETIC: IMPERIALISM 0x005aefa0
// TTechMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005aeff0
void TTechMgr::InitializeCityOrderCapabilityStateDefaults(void) {
  // Scalar capability defaults (0x180..0x262).
  perTechUnlockFlag180[0] = 1;
  perTechUnlockFlag180[1] = 1;
  perTechUnlockFlag180[2] = 1;
  // One flat 0x1a-byte clear covering perTechUnlockFlag180[3..0x1c].
  memset(&perTechUnlockFlag180[3], 0, 0x1a);
  memset(resourceTypeEnabled19d, 1, 4);
  resourceTypeEnabled19d[4] = 1;
  memset(&resourceTypeEnabled19d[5], 0, 8);
  resourceTypeEnabled19d[0xd] = 0;
  techSelectorShort1d2 = 3;
  activeZoneIndex1d4 = 4;
  memset(initFlags1c9, 0, sizeof(initFlags1c9));
  initFlags1c9[0] = 1;
  initFlags1c9[1] = 1;
  initFlags1c9[4] = 1;
  initFlags1c9[2] = 1;
  initFlags1c9[7] = 1;
  memset(initFlags1ab, 1, sizeof(initFlags1ab));
  memset(initFlags1af, 1, sizeof(initFlags1af));
  flag1c3 = 1;
  marker262 = 2;

  // Per-nation capability tables, in the original's two separate 7-nation passes.
  int n;
  for (n = 0; n < 7; ++n) {
    // orderCapRows: first three tech statuses = 2, rest cleared.
    orderCapRows277[n].techStatusByTechId[0] = 2;
    orderCapRows277[n].techStatusByTechId[1] = 2;
    orderCapRows277[n].techStatusByTechId[2] = 2;
    memset(&orderCapRows277[n].techStatusByTechId[3], 0, 0x1a);
    memset(&capRowsE4a6[n], 0, sizeof(CapRowE));
    memset(&capRowsB333[n], 0, sizeof(CapRowB));
    memset(&abilityActiveRows395[n], 0, sizeof(MilitaryCapRow));
    memset(&universityRecruitmentAvailabilityByNation467[n], 0,
           sizeof(UniversityRecruitmentAvailabilityRow));
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[0] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[1] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[4] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[2] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[7] = 1;
  }
  for (n = 0; n < 7; ++n) {
    // capabilityValueByNationAndResource: clear the row, set the default-unlocked columns.
    memset(capabilityValueByNationAndResource[n], 0, sizeof(capabilityValueByNationAndResource[n]));
    capabilityValueByNationAndResource[n][0x12] = 1;
    capabilityValueByNationAndResource[n][0x11] = 1;
    capabilityValueByNationAndResource[n][0x15] = 1;
    capabilityValueByNationAndResource[n][4] = 1;
    capabilityValueByNationAndResource[n][3] = 1;
    capabilityValueByNationAndResource[n][0x16] = 1;

    // The recruitment availability row is re-cleared and re-filled in the original's
    // second nation pass as well.
    memset(&universityRecruitmentAvailabilityByNation467[n], 0,
           sizeof(UniversityRecruitmentAvailabilityRow));
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[0] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[1] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[4] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[2] = 1;
    universityRecruitmentAvailabilityByNation467[n].availableByCategory[7] = 1;

    // Ability rows: ids 0..7 active by default plus 0x18/0x1b; the recruit/elite gate
    // ids (8/0x10) stay cleared.
    memset(abilityActiveRows395[n].abilityActiveById, 1, 8);
    abilityActiveRows395[n].abilityActiveById[0x18] = 1;
    abilityActiveRows395[n].abilityActiveById[0x1b] = 1;

    // capRowsB: first five resource types selected by default, rest cleared.
    memset(capRowsB333[n].selectedByResourceType, 1, 5);
    memset(&capRowsB333[n].selectedByResourceType[5], 0, 9);

    // nationCapRows: slots[0..7] = 0..7, slots[8] = 0x18, slots[9] = 0x1b.
    int j;
    for (j = 0; j < 8; ++j) {
      nationCapRows1e8[n].slots[j] = static_cast<short>(j);
    }
    nationCapRows1e8[n].slots[8] = 0x18;
    nationCapRows1e8[n].slots[9] = 0x1b;
  }

  packedRulePair264 = *reinterpret_cast<unsigned int*>(g_aTechItemPrerequisitePairs[30]);
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
  if (g_pSimMgr->multiplayerSessionRole == 0 ||
      (seed = static_cast<unsigned int>(g_pGameFlowState->queueSyncDword)) == 0) {
    // Genuine __cdecl free function declared (void); the guardrail-sanctioned arg-adjust cast
    // pushes the ignored 0 argument the original passes.
    seed = time(0);
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
  TObject::ReadFrom(stream);

  if (g_nSaveFormatVersion >= 0x27) {
    stream->ReadBytes(prioritySlots04, sizeof(prioritySlots04));
    SwapShortArrayBytes(prioritySlots04, 0x1d);
    stream->ReadBytes(capabilityValueByNationAndResource,
                      sizeof(capabilityValueByNationAndResource));
    SwapShortArrayBytes(capabilityValueByNationAndResource, 0xa1);
    stream->ReadBytes(&techSelectorShort1d2, 2);
    stream->ReadBytes(&activeZoneIndex1d4, 2);
    stream->ReadBytes(perTechUnlockFlag180, 0x1d);
    stream->ReadBytes(resourceTypeEnabled19d, sizeof(resourceTypeEnabled19d));
    stream->ReadBytes(initFlags1ab, 0x1e);
    stream->ReadBytes(initFlags1c9, sizeof(initFlags1c9));
    if (g_nSaveFormatVersion > 0x34) {
      stream->ReadBytes(&packedRulePair264, sizeof(packedRulePair264));
    }
  } else {
    stream->ReadBytes(prioritySlots04, sizeof(prioritySlots04));
    stream->ReadBytes(capabilityValueByNationAndResource, 0x2e);
    stream->ReadBytes(&techSelectorShort1d2, 2);
    stream->ReadBytes(&activeZoneIndex1d4, 2);
    stream->ReadBytes(perTechUnlockFlag180, 0x1d);
    stream->ReadBytes(resourceTypeEnabled19d, sizeof(resourceTypeEnabled19d));
    stream->ReadBytes(initFlags1ab, 0x1e);
    stream->ReadBytes(initFlags1c9, sizeof(initFlags1c9));
  }

  if (g_nSaveFormatVersion > 0xf) {
    stream->ReadBytes(nationCapRows1e8, sizeof(nationCapRows1e8));
    SwapShortArrayBytes(nationCapRows1e8, 0x46);
  }
  if (g_nSaveFormatVersion > 0x17) {
    stream->ReadBytes(orderCapRows277, sizeof(orderCapRows277));
    stream->ReadBytes(capRowsB333, sizeof(capRowsB333));
    stream->ReadBytes(abilityActiveRows395, sizeof(abilityActiveRows395));
    stream->ReadBytes(universityRecruitmentAvailabilityByNation467,
                      sizeof(universityRecruitmentAvailabilityByNation467));
    stream->ReadBytes(capRowsE4a6, sizeof(capRowsE4a6));
    SwapShortArrayBytes(capRowsE4a6, 0xcb);
  }
  if (g_nSaveFormatVersion > 0x18) {
    stream->ReadBytes(capabilityValueByNationAndResource,
                      sizeof(capabilityValueByNationAndResource));
    SwapShortArrayBytes(capabilityValueByNationAndResource, 0xa1);
  }
  if (g_nSaveFormatVersion > 0x1e) {
    stream->ReadBytes(&marker262, sizeof(marker262));
  }
  RecomputeGlobalCapabilityAverages();
}

// FUNCTION: IMPERIALISM 0x005af710
void TTechMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  WriteShortArrayElems(stream, prioritySlots04, 0x1d);
  WriteShortArrayElems(stream, &capabilityValueByNationAndResource[0][0], 0xa1);
  stream->WriteBytesSlot78(&techSelectorShort1d2, 2);
  stream->WriteBytesSlot78(&activeZoneIndex1d4, 2);
  stream->WriteBytesSlot78(perTechUnlockFlag180, 0x1d);
  stream->WriteBytesSlot78(resourceTypeEnabled19d, sizeof(resourceTypeEnabled19d));
  stream->WriteBytesSlot78(initFlags1ab, 0x1e);
  stream->WriteBytesSlot78(initFlags1c9, sizeof(initFlags1c9));
  stream->WriteBytesSlot78(&packedRulePair264, sizeof(packedRulePair264));
  WriteShortArrayElems(stream, nationCapRows1e8[0].slots, 0x46);
  stream->WriteBytesSlot78(orderCapRows277, sizeof(orderCapRows277));
  stream->WriteBytesSlot78(capRowsB333, sizeof(capRowsB333));
  stream->WriteBytesSlot78(abilityActiveRows395, sizeof(abilityActiveRows395));
  stream->WriteBytesSlot78(universityRecruitmentAvailabilityByNation467,
                           sizeof(universityRecruitmentAvailabilityByNation467));
  WriteShortArrayElems(stream, capRowsE4a6[0].completionYearOffsetByTechId, 0xcb);
  WriteShortArrayElems(stream, &capabilityValueByNationAndResource[0][0], 0xa1);
  stream->WriteBytesSlot78(&marker262, sizeof(marker262));
}

// FUNCTION: IMPERIALISM 0x005af980
void TTechMgr::CheckForAdvances() {
  const short economicTurn = g_pSimMgr->GetEconomicTurn();
  for (int techId = 3; techId < 0x1d; ++techId) {
    if (perTechUnlockFlag180[techId] == 0) {
      if (prioritySlots04[techId] == economicTurn) {
        ApplyCityOrderCapabilityUnlockByTechId(techId);
        g_pNewsMgr->AddMiscEvent(999, techId, 1);
      }
      continue;
    }

    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0 &&
          nation->diplomacyEligibilityA0 == 0 &&
          orderCapRows277[nationSlot].techStatusByTechId[techId] != 2) {
        nation->AddToTreasury(-g_anTechItemPurchaseCostBySlot_0066aae8[techId]);
        orderCapRows277[nationSlot].techStatusByTechId[techId] = 1;
        capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId] =
            static_cast<short>(g_pSimMgr->economicTurn / 4);
      }
    }
  }
}

// Turn-instruction handler body ("Tech"): unlocks techId on the city-order capability state,
// then for every nation that is either AI-ineligible (diplomacyEligibilityA0 == 0) or the
// forced target nation, stamps this tech's completion year (current quarter tick / 4) and
// applies its per-nation ability unlock.
// FUNCTION: IMPERIALISM 0x005afb10
void TTechMgr::ApplyTechUnlockAndQueueNationAbilityNotices(int techId, int forcedNationSlot) {
  this->ApplyCityOrderCapabilityUnlockByTechId(techId);
  TGreatPower** nationCursor = g_apNationStates;
  int nationSlot = 0;
  do {
    TGreatPower* nation = *nationCursor;
    if (nation->diplomacyEligibilityA0 == 0 || nationSlot == forcedNationSlot) {
      this->capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId] =
          static_cast<short>(g_pSimMgr->economicTurn / 4);
      this->HandleAbilityUnlock(techId, nationSlot);
    }
    ++nationCursor;
    ++nationSlot;
  } while (nationCursor < &g_apNationStates_End);
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
    resourceTypeEnabled19d[7] = 1;
    techSelectorShort1d2 = 7;
    resourceTypeEnabled19d[5] = 1;
    return;
  case 4:
    resourceTypeEnabled19d[6] = 1;
    return;
  case 0xf:
    resourceTypeEnabled19d[8] = 1;
    activeZoneIndex1d4 = 8;
    return;
  case 0xb:
    packedRulePair264 = *reinterpret_cast<unsigned int*>(g_aTechItemPrerequisitePairs[31]);
    return;
  case 0x15:
    resourceTypeEnabled19d[9] = 1;
    activeZoneIndex1d4 = 9;
    return;
  case 0x18:
    resourceTypeEnabled19d[0xb] = 1;
    techSelectorShort1d2 = 0xb;
    resourceTypeEnabled19d[0xa] = 1;
    return;
  case 0x1b:
    resourceTypeEnabled19d[0xc] = 1;
    activeZoneIndex1d4 = 0xc;
    resourceTypeEnabled19d[0xd] = 1;
    techSelectorShort1d2 = 0xd;
    return;
  case 0x16:
    packedRulePair264 = *reinterpret_cast<unsigned int*>(g_aTechItemPrerequisitePairs[32]);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x005afd00
void TTechMgr::HandleAbilityUnlock(int techId, int nationSlot) {
  if (orderCapRows277[nationSlot].techStatusByTechId[techId] == 2) {
    return;
  }
  orderCapRows277[nationSlot].techStatusByTechId[techId] = 2;

  // Late-era arms bonus scale: only for AI-eligible nations once the sim level passes 2.
  short eraOffset = 0;
  int simLevel = g_pSimMgr->difficultyLevel;
  if (simLevel >= 3 && g_apNationStates[nationSlot]->diplomacyEligibilityA0 == 0) {
    eraOffset = static_cast<short>(simLevel - 2);
  }

  switch (techId) {
  case 3:
    capabilityValueByNationAndResource[nationSlot][0] = 1;
    break;
  case 2:
    capabilityValueByNationAndResource[nationSlot][0x11] = 1;
    break;
  case 9:
    UpdateSelectionAndRecalculateScores(7, nationSlot);
    UpdateSelectionAndRecalculateScores(5, nationSlot);
    break;
  case 5:
    capabilityValueByNationAndResource[nationSlot][3] = 2;
    capabilityValueByNationAndResource[nationSlot][4] = 2;
    capabilityValueByNationAndResource[nationSlot][0x16] = 2;
    capabilityValueByNationAndResource[nationSlot][0x15] = 2;
    break;
  case 6:
    capabilityValueByNationAndResource[nationSlot][2] = 1;
    universityRecruitmentAvailabilityByNation467[nationSlot].availableByCategory[3] = 1;
    break;
  case 4:
    UpdateSelectionAndRecalculateScores(6, nationSlot);
    break;
  case 0xa:
    capabilityValueByNationAndResource[nationSlot][0x12] = 2;
    capabilityValueByNationAndResource[nationSlot][0x11] = 2;
    break;
  case 7:
    capabilityValueByNationAndResource[nationSlot][0x14] = 1;
    capabilityValueByNationAndResource[nationSlot][1] = 1;
    universityRecruitmentAvailabilityByNation467[nationSlot].availableByCategory[5] = 1;
    break;
  case 8:
    capabilityValueByNationAndResource[nationSlot][0] = 2;
    capabilityValueByNationAndResource[nationSlot][1] = 2;
    break;
  case 0xf:
    UpdateSelectionAndRecalculateScores(8, nationSlot);
    if (g_pSimMgr->GetActiveNationId() == nationSlot) {
      g_pStrategicMapViewSystem->RefreshCityCapabilityUiHandlesForActiveNation();
    }
    break;
  case 0xc:
    capabilityValueByNationAndResource[nationSlot][2] = 2;
    break;
  case 0x11:
    capabilityValueByNationAndResource[nationSlot][0x11] = 3;
    break;
  case 0x12:
    capabilityValueByNationAndResource[nationSlot][0x12] = 3;
    break;
  case 0x14:
    capabilityValueByNationAndResource[nationSlot][0x14] = 2;
    break;
  case 0xb:
    ActivateSlotAndUpdateUI(0xc, nationSlot);
    ActivateSlotAndUpdateUI(9, nationSlot);
    ActivateSlotAndUpdateUI(0x19, nationSlot);
    ActivateSlotAndUpdateUI(0x1c, nationSlot);
    break;
  case 0x10:
    capabilityValueByNationAndResource[nationSlot][0] = 3;
    capabilityValueByNationAndResource[nationSlot][1] = 3;
    break;
  case 0x15:
    UpdateSelectionAndRecalculateScores(9, nationSlot);
    break;
  case 0xd:
    ActivateSlotAndUpdateUI(0xe, nationSlot);
    ActivateSlotAndUpdateUI(0xf, nationSlot);
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + eraOffset * 10);
      city->VerifyStocks();
    }
    break;
  case 0x17:
    capabilityValueByNationAndResource[nationSlot][3] = 3;
    capabilityValueByNationAndResource[nationSlot][4] = 3;
    capabilityValueByNationAndResource[nationSlot][0x16] = 3;
    capabilityValueByNationAndResource[nationSlot][0x15] = 3;
    capabilityValueByNationAndResource[nationSlot][2] = 3;
    ActivateSlotAndUpdateUI(0x1a, nationSlot);
    break;
  case 0x13:
    capabilityValueByNationAndResource[nationSlot][6] = 1;
    universityRecruitmentAvailabilityByNation467[nationSlot].availableByCategory[8] = 1;
    break;
  case 0xe:
    ActivateSlotAndUpdateUI(8, nationSlot);
    ActivateSlotAndUpdateUI(0xd, nationSlot);
    ActivateSlotAndUpdateUI(0xa, nationSlot);
    ActivateSlotAndUpdateUI(0xb, nationSlot);
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + eraOffset * 10);
      city->VerifyStocks();
    }
    break;
  case 0x18:
    UpdateSelectionAndRecalculateScores(0xb, nationSlot);
    UpdateSelectionAndRecalculateScores(0xa, nationSlot);
    if (g_pSimMgr->GetActiveNationId() == nationSlot) {
      g_pStrategicMapViewSystem->RefreshCityCapabilityUiHandlesForActiveNation();
    }
    break;
  case 0x1a:
    capabilityValueByNationAndResource[nationSlot][6] = 2;
    capabilityValueByNationAndResource[nationSlot][0x14] = 3;
    break;
  case 0x1b:
    UpdateSelectionAndRecalculateScores(0xc, nationSlot);
    UpdateSelectionAndRecalculateScores(0xd, nationSlot);
    break;
  case 0x16:
    ActivateSlotAndUpdateUI(0x16, nationSlot);
    ActivateSlotAndUpdateUI(0x17, nationSlot);
    packedRulePair264 = *reinterpret_cast<unsigned int*>(g_aTechItemPrerequisitePairs[32]);
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + eraOffset * 20);
      city->VerifyStocks();
    }
    break;
  case 0x1c:
    capabilityValueByNationAndResource[nationSlot][6] = 3;
    ActivateSlotAndUpdateUI(0x14, nationSlot);
    ActivateSlotAndUpdateUI(0x15, nationSlot);
    break;
  case 0x19:
    ActivateSlotAndUpdateUI(0x10, nationSlot);
    ActivateSlotAndUpdateUI(0x11, nationSlot);
    ActivateSlotAndUpdateUI(0x12, nationSlot);
    ActivateSlotAndUpdateUI(0x13, nationSlot);
    ActivateSlotAndUpdateUI(0x1d, nationSlot);
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + eraOffset * 20);
      city->VerifyStocks();
    }
    break;
  default:
    break;
  }

  // Upgrade every owned, developed tile whose capability ceiling rose.
  short tileIndex;
  for (tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* record = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (record->ownerNationTag04 == nationSlot && (record->activeFlags1c & 1) != 0) {
      short maxCap = static_cast<char>(
          g_pGlobalMapState->FindMaxResourceCapabilityValueForTile(tileIndex, 0, nationSlot));
      if (static_cast<char>(
              g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, 0)) < maxCap) {
        g_pGlobalMapState->SetCivilianDevelopmentClassNibble(tileIndex, 0,
                                                             static_cast<unsigned char>(maxCap), 1);
      }
    }
  }
}

// Activates an ability in its slot group for a nation: marks the ability row, records
// the ability in the group slot, and for unit-order groups (1..8) reloads the city's
// TUnitOrder cost profile from g_aUnitOrderCostProfileByAbilityId (clearing the replaced
// ability); other groups upgrade the nation's matching military units.
// FUNCTION: IMPERIALISM 0x005b0340
void TTechMgr::ActivateSlotAndUpdateUI(int abilityId, int nationSlot) {
  short group = g_awTacticalUnitCategoryCodeBySlot[abilityId];
  abilityActiveRows395[nationSlot].abilityActiveById[abilityId] = 1;
  nationCapRows1e8[nationSlot].slots[group] = static_cast<short>(abilityId);
  if (group > 0 && group < 9) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0 && nation->city != 0) {
      TUnitOrder* order =
          static_cast<TUnitOrder*>(nation->city->orderSlotsE4[static_cast<short>(group + 0x18)]);
      order->AssertValid();
      abilityActiveRows395[nationSlot].abilityActiveById[order->resourceTypeIndex48] = 0;
      order->SetOrderCostProfile(g_aUnitOrderCostProfileByAbilityId[abilityId][0],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][1],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][2],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][3],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][4],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][5],
                                 g_aUnitOrderCostProfileByAbilityId[abilityId][6]);
    }
  } else {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0) {
      CIterator cursor(g_apTerrainTypeDescriptorTable[nationSlot]->militaryUnitList44);
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
      while (cursor.More()) {
        if (unit->GetCategory() == group) {
          unit->Upgrade();
        }
        unit = static_cast<TMilitaryUnit*>(cursor.Advance());
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b0500
void TTechMgr::UpdateSelectionAndRecalculateScores(int resourceType, int nationSlot) {
  int slotMap[14];
  slotMap[0] = 0;
  slotMap[1] = 0;
  slotMap[2] = 1;
  slotMap[3] = 4;
  slotMap[4] = 5;
  slotMap[5] = 2;
  slotMap[6] = 3;
  slotMap[7] = 6;
  slotMap[8] = 7;
  slotMap[9] = 7;
  slotMap[10] = 2;
  slotMap[11] = 6;
  slotMap[12] = 7;
  slotMap[13] = 6;
  int mapped = slotMap[resourceType];

  int selectedGroup = GetResourceDescriptorWord20ByType(static_cast<short>(resourceType));
  int i;
  for (i = 0; i < 0xe; ++i) {
    if (GetResourceDescriptorWord20ByType(static_cast<short>(i)) == selectedGroup &&
        i != resourceType) {
      capRowsB333[nationSlot].selectedByResourceType[i] = 0;
    }
  }
  capRowsB333[nationSlot].selectedByResourceType[resourceType] = 1;

  int scoreSum = 0;
  int matchedCount = 0;
  int remainingOwned = 0;
  if (g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
    return;
  }
  if (((g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0) == 0) {
    return;
  }

  TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
  TUnitOrder* order =
      static_cast<TUnitOrder*>(city->orderSlotsE4[static_cast<short>(mapped + 0x2b)]);
  if ((mapped == 6 || mapped == 7) && order->resourceTypeIndex48 != 0) {
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    TUnitOrder* olderOrder =
        static_cast<TUnitOrder*>(city->orderSlotsE4[static_cast<short>(mapped + 0x29)]);
    capRowsB333[nationSlot].selectedByResourceType[olderOrder->resourceTypeIndex48] = 0;
    olderOrder->resourceTypeIndex48 = order->resourceTypeIndex48;
  } else if (resourceType == 10) {
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    static_cast<TUnitOrder*>(city->orderSlotsE4[0x2b])->resourceTypeIndex48 = 5;
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    static_cast<TUnitOrder*>(city->orderSlotsE4[0x2c])->resourceTypeIndex48 = 6;
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    static_cast<TUnitOrder*>(city->orderSlotsE4[0x2e])->resourceTypeIndex48 = 0;
  }
  order->resourceTypeIndex48 = static_cast<short>(resourceType);

  TShip* node = TShip::GetFirst();
  while (node != 0) {
    if (node->nation == nationSlot &&
        capRowsB333[nationSlot].selectedByResourceType[node->type] == 0) {
      scoreSum += static_cast<short>(node->experience / 100);
      ++matchedCount;
      TAdmiral* admiral = node->admiral;
      TShip* next = node->next;
      if (admiral != 0) {
        admiral->AssignToShip(0);
      }
      node->Sink();
      if (admiral != 0) {
        admiral->ReassignThyself();
      }
      node = next;
    } else {
      if (node->nation == nationSlot) {
        ++remainingOwned;
      }
      node = node->next;
    }
  }

  if (nationSlot == g_pSimMgr->GetActiveNationId() && matchedCount > 0) {
    CString countString;
    CString templateText;
    CString formattedMessage;
    countString.Format(g_szDecimalFormat, matchedCount);
    if (remainingOwned > 0) {
      g_pSimMgr->GetString(0x2739, 2, &templateText);
      scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(countString));
    } else {
      g_pSimMgr->GetString(0x2739, 3, &templateText);
      scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(countString));
    }
    g_pUiRuntimeContext->ModalMessage(formattedMessage, g_ptTechCapabilityModalMessage, 2, 0);
  }

  for (node = TShip::GetFirst(); node != 0; node = node->next) {
    if (node->nation == nationSlot) {
      node->Victory(static_cast<short>(scoreSum / remainingOwned));
    }
  }

  RecomputeGlobalCapabilityAverages();
}

// FUNCTION: IMPERIALISM 0x005b0a20
bool TTechMgr::AreTechItemPrerequisitePairCompleted(int techId, int nationSlot) {
  short p1 = g_aTechItemPrerequisitePairs[techId][0];
  unsigned char* p1StatusByNation = &orderCapRows277[0].techStatusByTechId[p1];
  if (p1StatusByNation[nationSlot * sizeof(OrderCapRow)] == 2) {
    short p2 = g_aTechItemPrerequisitePairs[techId][1];
    unsigned char* p2StatusByNation = &orderCapRows277[0].techStatusByTechId[p2];
    if (p2StatusByNation[nationSlot * sizeof(OrderCapRow)] == 2) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005b0a90
void TTechMgr::SelectMissingTechItemPrerequisitesFromPair(int techId, int nationSlot, int* missing1,
                                                          int* missing2) {
  short p1 = g_aTechItemPrerequisitePairs[techId][0];
  if (orderCapRows277[nationSlot].techStatusByTechId[p1] == 2) {
    *missing1 = g_aTechItemPrerequisitePairs[techId][1];
    *missing2 = 0;
  } else {
    *missing1 = p1;
    short p2 = g_aTechItemPrerequisitePairs[techId][1];
    *missing2 = (orderCapRows277[nationSlot].techStatusByTechId[p2] != 2) ? p2 : 0;
  }
}

// Purchases a tech-item slot for a nation: spends the slot's cost from the nation's
// field-0x10 metric (AddToTreasury with the negated cost), marks the slot
// status byte 1 in the nation's orderCapRows277 row, and stamps the current quarter
// tick / 4 into the parallel capRowsE4a6 word.
// FUNCTION: IMPERIALISM 0x005b0b30
void TTechMgr::ApplyTechItemPurchaseCostAndState(int slot, int nationIndex) {
  g_apNationStates[nationIndex]->AddToTreasury(-g_anTechItemPurchaseCostBySlot_0066aae8[slot]);
  orderCapRows277[nationIndex].techStatusByTechId[slot] = 1;
  capRowsE4a6[nationIndex].completionYearOffsetByTechId[slot] =
      static_cast<short>(g_pSimMgr->economicTurn / 4);
}

// Inverse of ApplyTechItemPurchaseCostAndState: refunds the slot's cost back to the
// nation's field-0x10 metric and clears both the status byte and the capRowsE4a6 word.
// FUNCTION: IMPERIALISM 0x005b0bb0
void TTechMgr::RefundTechItemPurchaseCostAndClearState(int slot, int nationIndex) {
  g_apNationStates[nationIndex]->AddToTreasury(g_anTechItemPurchaseCostBySlot_0066aae8[slot]);
  orderCapRows277[nationIndex].techStatusByTechId[slot] = 0;
  capRowsE4a6[nationIndex].completionYearOffsetByTechId[slot] = 0;
}

// FUNCTION: IMPERIALISM 0x005b0c20
short TTechMgr::ConsumeFirstPendingAbilityUnlock(short nationSlot) {
  for (int techId = 0; techId < 0x1d; ++techId) {
    if (orderCapRows277[nationSlot].techStatusByTechId[techId] == 1) {
      HandleAbilityUnlock(techId, nationSlot);
      return static_cast<short>(techId);
    }
  }
  return -1;
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
  if (orderCapRows277[nNationId].techStatusByTechId[0x16] != 0) {
    return 3;
  }
  return (orderCapRows277[nNationId].techStatusByTechId[0x0b] != 0) + 1;
}
