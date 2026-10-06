#include "game/tactical_ui/TTechMgr.h"

#include "decomp_types.h"
#include "game/core/runtime_prng_seed.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_ui_globals.h"

#include <string.h>

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/navy/TAdmiral.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/navy/TShip.h"
#include "game/core/TStream.h"
#include "game/navy_order.h"
#include "game/nation_stream_serialization.h"
#include "game/navy/TTaskForce.h"
#include "game/city/TUnitOrder.h"
#include "game/city/TShipOrder.h"
#include "game/ui_core/TViewMgr.h"
#include "game/military/mapped_flavor_text.h"

TTechMgr* g_pTechMgr = 0;

// FUNCTION: IMPERIALISM 0x005572d0
short GetEnabledIndustryCapabilitySlotByClass(short classId) {
  short slot = 13;
  const IndustryCapabilityClassSlotEntry* entry = &g_aIndustryCapabilityClassSlotTable[13];
  while (entry->classId != classId || g_pTechMgr->resourceTypeEnabled[slot] == 0) {
    entry--;
    slot--;
    if (entry == g_aIndustryCapabilityClassSlotTable) {
      return 0;
    }
  }
  return slot;
}

IMPLEMENT_DYNCREATE(TTechMgr, TObject)

// FUNCTION: IMPERIALISM 0x005aef80
TTechMgr::TTechMgr() {}

// FUNCTION: IMPERIALISM 0x005aefd0
TTechMgr::~TTechMgr() {}

// FUNCTION: IMPERIALISM 0x005aeff0
void TTechMgr::InitializeCityOrderCapabilityStateDefaults(void) {
  // Scalar capability defaults (0x180..0x262).
  perTechUnlockFlag[0] = 1;
  perTechUnlockFlag[1] = 1;
  perTechUnlockFlag[2] = 1;
  // One flat 0x1a-byte clear covering perTechUnlockFlag[3..0x1c].
  memset(&perTechUnlockFlag[3], 0, 0x1a);
  memset(resourceTypeEnabled, 1, 4);
  resourceTypeEnabled[4] = 1;
  memset(&resourceTypeEnabled[5], 0, 8);
  resourceTypeEnabled[0xd] = 0;
  techSelectorShort = 3;
  activeZoneIndex = 4;
  memset(initFlags1c9, 0, sizeof(initFlags1c9));
  initFlags1c9[0] = 1;
  initFlags1c9[1] = 1;
  initFlags1c9[4] = 1;
  initFlags1c9[2] = 1;
  initFlags1c9[7] = 1;
  memset(initFlags1ab, 1, sizeof(initFlags1ab));
  memset(initFlags1af, 1, sizeof(initFlags1af));
  flag1c3 = true;
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
    memset(&abilityActiveRows[n], 0, sizeof(MilitaryCapRow));
    memset(&universityRecruitmentAvailabilityByNation[n], 0,
           sizeof(UniversityRecruitmentAvailabilityRow));
    universityRecruitmentAvailabilityByNation[n].availableByCategory[0] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[1] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[4] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[2] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[7] = 1;
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

    memset(&universityRecruitmentAvailabilityByNation[n], 0,
           sizeof(UniversityRecruitmentAvailabilityRow));
    universityRecruitmentAvailabilityByNation[n].availableByCategory[0] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[1] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[4] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[2] = 1;
    universityRecruitmentAvailabilityByNation[n].availableByCategory[7] = 1;

    memset(abilityActiveRows[n].abilityActiveById, 1, 8);
    abilityActiveRows[n].abilityActiveById[0x18] = 1;
    abilityActiveRows[n].abilityActiveById[0x1b] = 1;

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

  activePrerequisitePair = g_aTechItemPrerequisitePairs[30];
  RecomputeGlobalCapabilityAverages();
}

// FUNCTION: IMPERIALISM 0x005af330
void TTechMgr::GenerateRandomCapabilityPrioritySlots() {
  prioritySlots[1] = 0;
  prioritySlots[2] = 0;
  prioritySlots[0] = 0;

  unsigned int seed;
  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone ||
      (seed = static_cast<unsigned int>(g_pGameFlowState->queueSyncDword)) == 0) {
    seed = static_cast<unsigned int>(ClockDerivedPrngSeed());
  }

  short* pnOutputSlotCursor = &prioritySlots[3];
  int nSelectedSlotCount = 3;
  for (short* pnRangePairCursor = &g_anCapabilityPriorityRangeData_0066ABA4[1];
       pnRangePairCursor < &g_anCapabilityPriorityRangeData_0066ABA4[53]; pnRangePairCursor += 2) {
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
      short* pnExistingSlotCursor = &prioritySlots[0];
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
    stream->ReadBytes(prioritySlots, sizeof(prioritySlots));
    SwapShortArrayBytes(prioritySlots, 0x1d);
    stream->ReadBytes(capabilityValueByNationAndResource,
                      sizeof(capabilityValueByNationAndResource));
    SwapShortArrayBytes(capabilityValueByNationAndResource, 0xa1);
    stream->ReadBytes(&techSelectorShort, 2);
    stream->ReadBytes(&activeZoneIndex, 2);
    stream->ReadBytes(perTechUnlockFlag, 0x1d);
    stream->ReadBytes(resourceTypeEnabled, sizeof(resourceTypeEnabled));
    stream->ReadBytes(initFlags1ab, 0x1e);
    stream->ReadBytes(initFlags1c9, sizeof(initFlags1c9));
    if (g_nSaveFormatVersion > 0x34) {
      stream->ReadBytes(&activePrerequisitePair, sizeof(activePrerequisitePair));
    }
  } else {
    stream->ReadBytes(prioritySlots, sizeof(prioritySlots));
    stream->ReadBytes(capabilityValueByNationAndResource, 0x2e);
    stream->ReadBytes(&techSelectorShort, 2);
    stream->ReadBytes(&activeZoneIndex, 2);
    stream->ReadBytes(perTechUnlockFlag, 0x1d);
    stream->ReadBytes(resourceTypeEnabled, sizeof(resourceTypeEnabled));
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
    stream->ReadBytes(abilityActiveRows, sizeof(abilityActiveRows));
    stream->ReadBytes(universityRecruitmentAvailabilityByNation,
                      sizeof(universityRecruitmentAvailabilityByNation));
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
  WriteShortArrayElems(stream, prioritySlots, 0x1d);
  WriteShortArrayElems(stream, &capabilityValueByNationAndResource[0][0], 0xa1);
  stream->WriteBytes(&techSelectorShort, 2);
  stream->WriteBytes(&activeZoneIndex, 2);
  stream->WriteBytes(perTechUnlockFlag, 0x1d);
  stream->WriteBytes(resourceTypeEnabled, sizeof(resourceTypeEnabled));
  stream->WriteBytes(initFlags1ab, 0x1e);
  stream->WriteBytes(initFlags1c9, sizeof(initFlags1c9));
  stream->WriteBytes(&activePrerequisitePair, sizeof(activePrerequisitePair));
  WriteShortArrayElems(stream, nationCapRows1e8[0].slots, 0x46);
  stream->WriteBytes(orderCapRows277, sizeof(orderCapRows277));
  stream->WriteBytes(capRowsB333, sizeof(capRowsB333));
  stream->WriteBytes(abilityActiveRows, sizeof(abilityActiveRows));
  stream->WriteBytes(universityRecruitmentAvailabilityByNation,
                     sizeof(universityRecruitmentAvailabilityByNation));
  WriteShortArrayElems(stream, capRowsE4a6[0].completionYearOffsetByTechId, 0xcb);
  WriteShortArrayElems(stream, &capabilityValueByNationAndResource[0][0], 0xa1);
  stream->WriteBytes(&marker262, sizeof(marker262));
}

// FUNCTION: IMPERIALISM 0x005af980
void TTechMgr::CheckForAdvances() {
  const short economicTurn = g_pSimMgr->GetEconomicTurn();
  for (int techId = 3; techId < 0x1d; ++techId) {
    if (perTechUnlockFlag[techId] == 0) {
      if (prioritySlots[techId] == economicTurn) {
        ApplyCityOrderCapabilityUnlockByTechId(techId);
        g_pNewsMgr->AddMiscEvent(999, techId, true);
      }
      continue;
    }

    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot)) &&
          nation->diplomacyEligibility == 0 &&
          orderCapRows277[nationSlot].techStatusByTechId[techId] != 2) {
        nation->AddToTreasury(-g_anTechItemPurchaseCostBySlot_0066aae8[techId]);
        orderCapRows277[nationSlot].techStatusByTechId[techId] = 1;
        capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId] =
            static_cast<short>(g_pSimMgr->economicTurn / 4);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005afb10
void TTechMgr::ApplyTechUnlockAndQueueNationAbilityNotices(int techId, int forcedNationSlot) {
  this->ApplyCityOrderCapabilityUnlockByTechId(techId);
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation->diplomacyEligibility == 0 || nationSlot == forcedNationSlot) {
      this->capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId] =
          static_cast<short>(g_pSimMgr->economicTurn / 4);
      this->HandleAbilityUnlock(techId, nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005afba0
void TTechMgr::ApplyCityOrderCapabilityUnlockByTechId(int nTechId) {
  marker262 = static_cast<short>(nTechId);
  perTechUnlockFlag[nTechId] = 1;
  switch (nTechId) {
  case 9:
    resourceTypeEnabled[7] = 1;
    techSelectorShort = 7;
    resourceTypeEnabled[5] = 1;
    return;
  case 4:
    resourceTypeEnabled[6] = 1;
    return;
  case 0xf:
    resourceTypeEnabled[8] = 1;
    activeZoneIndex = 8;
    return;
  case 0xb:
    activePrerequisitePair = g_aTechItemPrerequisitePairs[31];
    return;
  case 0x15:
    resourceTypeEnabled[9] = 1;
    activeZoneIndex = 9;
    return;
  case 0x18:
    resourceTypeEnabled[0xb] = 1;
    techSelectorShort = 0xb;
    resourceTypeEnabled[0xa] = 1;
    return;
  case 0x1b:
    resourceTypeEnabled[0xc] = 1;
    activeZoneIndex = 0xc;
    resourceTypeEnabled[0xd] = 1;
    techSelectorShort = 0xd;
    return;
  case 0x16:
    activePrerequisitePair = g_aTechItemPrerequisitePairs[32];
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
  if (simLevel >= 3 && g_apNationStates[nationSlot]->diplomacyEligibility == 0) {
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
    universityRecruitmentAvailabilityByNation[nationSlot].availableByCategory[3] = 1;
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
    universityRecruitmentAvailabilityByNation[nationSlot].availableByCategory[5] = 1;
    break;
  case 8:
    capabilityValueByNationAndResource[nationSlot][0] = 2;
    capabilityValueByNationAndResource[nationSlot][1] = 2;
    break;
  case 0xf:
    UpdateSelectionAndRecalculateScores(8, nationSlot);
    if (g_pSimMgr->GetPlayerCountry() == nationSlot) {
      g_pMacViewMgr->RefreshCityCapabilityUiHandlesForActiveNation();
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
      city->cityStockArms = static_cast<short>(city->cityStockArms + eraOffset * 10);
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
    universityRecruitmentAvailabilityByNation[nationSlot].availableByCategory[8] = 1;
    break;
  case 0xe:
    ActivateSlotAndUpdateUI(8, nationSlot);
    ActivateSlotAndUpdateUI(0xd, nationSlot);
    ActivateSlotAndUpdateUI(0xa, nationSlot);
    ActivateSlotAndUpdateUI(0xb, nationSlot);
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArms = static_cast<short>(city->cityStockArms + eraOffset * 10);
      city->VerifyStocks();
    }
    break;
  case 0x18:
    UpdateSelectionAndRecalculateScores(0xb, nationSlot);
    UpdateSelectionAndRecalculateScores(0xa, nationSlot);
    if (g_pSimMgr->GetPlayerCountry() == nationSlot) {
      g_pMacViewMgr->RefreshCityCapabilityUiHandlesForActiveNation();
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
    activePrerequisitePair = g_aTechItemPrerequisitePairs[32];
    if (eraOffset != 0) {
      TCity* city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
      city->cityStockArms = static_cast<short>(city->cityStockArms + eraOffset * 20);
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
      city->cityStockArms = static_cast<short>(city->cityStockArms + eraOffset * 20);
      city->VerifyStocks();
    }
    break;
  default:
    break;
  }

  // Upgrade every owned, developed tile whose capability ceiling rose.
  short tileIndex;
  for (tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecord* record = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (record->ownerNationTag04 == nationSlot && (record->activeFlags1c & 1) != 0) {
      short maxCap =
          static_cast<char>(g_pGlobalMapState->GetMaxDevelopmentLevel(tileIndex, 0, nationSlot));
      if (static_cast<char>(g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(
              tileIndex, false)) < maxCap) {
        g_pGlobalMapState->SetDevelopmentLevel(tileIndex, false, static_cast<unsigned char>(maxCap),
                                               true);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b0340
void TTechMgr::ActivateSlotAndUpdateUI(int abilityId, int nationSlot) {
  short group = g_awTacticalUnitCategoryCodeBySlot[abilityId];
  abilityActiveRows[nationSlot].abilityActiveById[abilityId] = 1;
  nationCapRows1e8[nationSlot].slots[group] = static_cast<short>(abilityId);
  if (group > 0 && group < 9) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0 && nation->city != 0) {
      TUnitOrder* order = nation->city->buildOrderSlots[static_cast<short>(group - 1)];
      order->AssertValid();
      abilityActiveRows[nationSlot].abilityActiveById[order->resourceTypeIndex] = 0;
      order->ReplaceOrder(g_aUnitOrderCostProfileByAbilityId[abilityId][0],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][1],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][2],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][3],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][4],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][5],
                          g_aUnitOrderCostProfileByAbilityId[abilityId][6]);
    }
  } else {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot))) {
      CIterator cursor(g_apTerrainTypeDescriptorTable[nationSlot]->militaryUnitList);
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

  int selectedGroup = TShip::GetTypeToolbarSlot(static_cast<short>(resourceType));
  int i;
  for (i = 0; i < 0xe; ++i) {
    if (TShip::GetTypeToolbarSlot(static_cast<short>(i)) == selectedGroup && i != resourceType) {
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
  TShipOrder* order = city->shipOrderSlots[static_cast<short>(mapped)];
  if ((mapped == 6 || mapped == 7) && order->resourceTypeIndex != 0) {
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    TUnitOrder* olderOrder = city->buildOrderSlots[static_cast<short>(mapped + 0x10)];
    capRowsB333[nationSlot].selectedByResourceType[olderOrder->resourceTypeIndex] = 0;
    olderOrder->resourceTypeIndex = order->resourceTypeIndex;
  } else if (resourceType == 10) {
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    city->shipOrderSlots[0]->resourceTypeIndex = 5;
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    city->shipOrderSlots[1]->resourceTypeIndex = 6;
    city = (g_apNationStates[nationSlot] != 0) ? g_apNationStates[nationSlot]->city : 0;
    city->shipOrderSlots[3]->resourceTypeIndex = 0;
  }
  order->resourceTypeIndex = static_cast<short>(resourceType);

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

  if (nationSlot == g_pSimMgr->GetPlayerCountry() && matchedCount > 0) {
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
    g_pViewMgr->ModalMessage(formattedMessage, g_ptTechCapabilityModalMessage, 2, 0);
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
  short primaryPrerequisiteTechId = g_aTechItemPrerequisitePairs[techId].primaryTechId;
  unsigned char* primaryStatusByNation =
      &orderCapRows277[0].techStatusByTechId[primaryPrerequisiteTechId];
  if (primaryStatusByNation[nationSlot * sizeof(OrderCapRow)] == 2) {
    short secondaryPrerequisiteTechId = g_aTechItemPrerequisitePairs[techId].secondaryTechId;
    unsigned char* secondaryStatusByNation =
        &orderCapRows277[0].techStatusByTechId[secondaryPrerequisiteTechId];
    if (secondaryStatusByNation[nationSlot * sizeof(OrderCapRow)] == 2) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005b0a90
void TTechMgr::GetPreReqs(int techId, int nationSlot, int* missingPrimaryTechId,
                          int* missingSecondaryTechId) {
  short primaryPrerequisiteTechId = g_aTechItemPrerequisitePairs[techId].primaryTechId;
  if (orderCapRows277[nationSlot].techStatusByTechId[primaryPrerequisiteTechId] == 2) {
    *missingPrimaryTechId = g_aTechItemPrerequisitePairs[techId].secondaryTechId;
    *missingSecondaryTechId = 0;
  } else {
    *missingPrimaryTechId = primaryPrerequisiteTechId;
    short secondaryPrerequisiteTechId = g_aTechItemPrerequisitePairs[techId].secondaryTechId;
    *missingSecondaryTechId =
        (orderCapRows277[nationSlot].techStatusByTechId[secondaryPrerequisiteTechId] != 2)
            ? secondaryPrerequisiteTechId
            : 0;
  }
}

// FUNCTION: IMPERIALISM 0x005b0b30
void TTechMgr::ApplyTechItemPurchaseCostAndState(int slot, int nationIndex) {
  g_apNationStates[nationIndex]->AddToTreasury(-g_anTechItemPurchaseCostBySlot_0066aae8[slot]);
  orderCapRows277[nationIndex].techStatusByTechId[slot] = 1;
  capRowsE4a6[nationIndex].completionYearOffsetByTechId[slot] =
      static_cast<short>(g_pSimMgr->economicTurn / 4);
}

// FUNCTION: IMPERIALISM 0x005b0bb0
void TTechMgr::RefundTechItemPurchaseCostAndClearState(int slot, int nationIndex) {
  g_apNationStates[nationIndex]->AddToTreasury(g_anTechItemPurchaseCostBySlot_0066aae8[slot]);
  orderCapRows277[nationIndex].techStatusByTechId[slot] = 0;
  capRowsE4a6[nationIndex].completionYearOffsetByTechId[slot] = 0;
}

// FUNCTION: IMPERIALISM 0x005b0c20
short TTechMgr::GetNextNewAdvance(short nationSlot) {
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
  prioritySlots[index] = static_cast<short>(value * 4);
}

// FUNCTION: IMPERIALISM 0x005b0ca0
int TTechMgr::GetNationFortLevelCap(int nNationId) {
  if (orderCapRows277[nNationId].techStatusByTechId[0x16] != 0) {
    return 3;
  }
  return (orderCapRows277[nNationId].techStatusByTechId[0x0b] != 0) + 1;
}
