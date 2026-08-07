#include "RuntimeGameSnapshot.h"

#include "RuntimeJson.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/debug/TLaborPool.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/nation_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TBeachheadMission.h"
#include "game/map/TBlockadePortMission.h"
#include "game/map/TMission.h"
#include "game/map/TNavyMission.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/military/TArmyMission.h"
#include "game/military/TAttackProvinceMission.h"
#include "game/military/TCivUnit.h"
#include "game/military/TInvadeMission.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/nation/TLandSaleEvent.h"
#include "game/nation/TTurnStartEvent.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/CIterator.h"
#include "game/ui_screens/TSimMgr.h"

#include <string.h>

// VC5 libcmt rand.obj stores the thread-local LCG state at +0x14 in the block returned
// by _getptd. This test-only observation is backed by the vendored rand.obj disassembly;
// production source continues to use the ordinary CRT rand/srand API.
extern "C" void* __cdecl _getptd(void);

namespace {

unsigned int RuntimeFnv1a(const CString& value) {
  unsigned int hash = 2166136261U;
  const unsigned char* bytes =
      static_cast<const unsigned char*>(static_cast<const void*>(static_cast<LPCSTR>(value)));
  for (int index = 0; index < value.GetLength(); ++index) {
    hash ^= bytes[index];
    hash *= 16777619U;
  }
  return hash;
}

CString RuntimeHashText(const CString& value) {
  CString text;
  text.Format("%08x", RuntimeFnv1a(value));
  return text;
}

unsigned int RuntimeCrtRandState() {
  struct CrtThreadDataPrefix {
    unsigned char prefix00[0x14];
    unsigned int randState14;
  };
  CrtThreadDataPrefix* threadData = static_cast<CrtThreadDataPrefix*>(_getptd());
  return threadData != 0 ? threadData->randState14 : 0;
}

void AppendShortArray(CString& json, const short* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", static_cast<int>(values[index]));
    json += item;
  }
  json += "]";
}

void AppendIntArray(CString& json, const int* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", values[index]);
    json += item;
  }
  json += "]";
}

void AppendSignedByteArray(CString& json, const signed char* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", static_cast<int>(values[index]));
    json += item;
  }
  json += "]";
}

void AppendUnsignedByteArray(CString& json, const unsigned char* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%u", index == 0 ? "" : ",", static_cast<unsigned int>(values[index]));
    json += item;
  }
  json += "]";
}

unsigned int FloatBits(float value) {
  unsigned int bits = 0;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
}

void AppendLaborPool(CString& json, const TLaborPool* pool) {
  if (pool == 0) {
    json += "null";
    return;
  }
  CString values;
  values.Format("[%d,%d,%d]", static_cast<int>(pool->lowSkillCount04),
                static_cast<int>(pool->mediumSkillCount06),
                static_cast<int>(pool->highSkillCount08));
  json += values;
}

CString CaptureMetadata(const RuntimeRun& run) {
  // TSimMgr::mode selects the current presentation flow and changes while a saved game is
  // reopened. It is intentionally absent: the canonical snapshot owns simulation state, not the
  // screen used to reach it.
  CString json;
  json.Format("{\"scenario_map_index_plus_one\":%d,\"economic_turn\":%d,\"turn_state\":%d,"
              "\"difficulty\":%d,\"active_nation\":%d,\"selected_nation\":%d,"
              "\"persistent_unit_id_counter\":%d}",
              g_pSimMgr != 0 ? g_pSimMgr->scenarioMapIndexPlusOne : 0,
              g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1,
              g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1,
              g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
              g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1, run.SelectedNationSlot(),
              g_pSimMgr != 0 ? g_pSimMgr->field_64 : 0);
  return json;
}

CString CaptureRng(const RuntimeRun& run) {
  CString json;
  json.Format("{\"runtime_seed\":%u,\"crt_rand_state\":%u,\"map_generation_lcg\":%u,"
              "\"zone_status_lcg\":%u}",
              run.Seed(), RuntimeCrtRandState(), g_mapGenLcgState_006a38e8,
              g_zoneStatusCodePrngSeed_006a5aec);
  return json;
}

CString CaptureWorld() {
  CString json;
  json.Format("{\"width\":108,\"height\":60,\"wraps_horizontally\":%s,\"tiles\":[",
              g_pGlobalMapState->hexNeighborWrapHorizontally == 0 ? "true" : "false");
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    CString row;
    row.Format(
        "%s[%d,%d,%d,%d,%d,%d,%d,%u,%d,%u]", tileIndex == 0 ? "" : ",",
        static_cast<int>(tile.GetTerrainKind()), static_cast<int>(tile.ownerNationTag04),
        static_cast<int>(tile.formerOwnerNationTag03), static_cast<int>(tile.cityRecordIndex),
        static_cast<int>(tile.developmentClassNibbles0c),
        static_cast<int>(tile.resourceTypeByEdge[0]), static_cast<int>(tile.resourceTypeByEdge[1]),
        static_cast<unsigned int>(tile.railFlags17), static_cast<int>(tile.tileActionState16),
        static_cast<unsigned int>(tile.activeFlags1c));
    json += row;
  }
  json += "]}";
  return json;
}

CString CaptureNations() {
  CString json("{\"records\":[");
  for (int slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    CString row;
    row.Format("%s{\"slot\":%d,\"kind\":\"%s\",\"present\":%s", slot == 0 ? "" : ",", slot,
               slot < kMajorNationCount ? "major" : "minor", country != 0 ? "true" : "false");
    json += row;
    if (country == 0) {
      json += "}";
      continue;
    }

    row.Format(",\"nation_slot\":%d,\"encoded_nation_slot\":%d,\"owner_nation\":%d,"
               "\"treasury\":%d,\"home_tile\":%d,\"need_level_by_nation\":",
               static_cast<int>(country->nationSlot), static_cast<int>(country->encodedNationSlot),
               static_cast<int>(country->DecodeOwnerNationSlot()), country->treasuryValue10,
               country->homeTileIndex);
    json += row;
    AppendShortArray(json, country->needLevelByNation, kNationSlotCount);

    json += ",\"major\":";
    TGreatPower* nation = slot < kMajorNationCount ? g_apNationStates[slot] : 0;
    if (nation == 0) {
      json += "null";
    } else {
      row.Format("{\"diplomacy_eligible\":%u,\"capacities\":[%d,%d,%d,%d],"
                 "\"grant_total_cost\":%d,\"unfilled_trade_offer_count\":%d,"
                 "\"diplomacy_policy_by_nation\":",
                 static_cast<unsigned int>(nation->diplomacyEligibilityA0),
                 static_cast<int>(nation->availableMerchantCapacity),
                 static_cast<int>(nation->merchantCapacity),
                 static_cast<int>(nation->transportCapacity),
                 static_cast<int>(nation->reservedTransportCapacity), nation->grantTotalCost,
                 static_cast<int>(nation->unfilledTradeOfferCount));
      json += row;
      AppendShortArray(json, nation->diplomacyPolicyByNation, kNationSlotCount);
      json += ",\"diplomacy_grant_by_nation\":";
      AppendShortArray(json, nation->diplomacyGrantByNation, kNationSlotCount);
      json += ",\"need_current_by_type\":";
      AppendShortArray(json, nation->needCurrentByType, kResourceKindCount);
      json += ",\"need_target_by_type\":";
      AppendShortArray(json, nation->needTargetByType, kResourceKindCount);
      json += ",\"relation_delta_current\":";
      AppendShortArray(json, nation->relationDeltaCurrent, kResourceKindCount);
      json += ",\"purchased_items_by_resource\":";
      AppendShortArray(json, nation->purchasedItemsByResource, kResourceKindCount);
      json += ",\"item_potentials\":";
      AppendShortArray(json, nation->itemPotentials, kResourceKindCount);
      json += ",\"unfilled_trade_turns_by_resource\":";
      AppendShortArray(json, nation->unfilledTradeTurnCountsByResource, kResourceKindCount);
      json += ",\"transported_items_by_resource\":";
      AppendShortArray(json, nation->transportedItemsByResource, kResourceKindCount);
      json += ",\"remembered_trade_offers_by_resource\":";
      AppendShortArray(json, nation->rememberedTradeOffersByResource, kResourceKindCount);
      json += ",\"aid_allocation_matrix\":";
      AppendIntArray(json, nation->aidAllocationMatrix, 0x170);
      row.Format(",\"budget_pool_base\":%d,\"budget_pool_delta\":%d,"
                 "\"special_resource_trade_balance\":%d,\"candidate_nation_flags\":",
                 nation->budgetPoolBase, nation->budgetPoolDelta, nation->field910);
      json += row;
      AppendUnsignedByteArray(json, nation->candidateNationFlags, kNationSlotCount);
      row.Format(",\"scenario_initialized\":%u,\"turn_finished\":%u,"
                 "\"pending_action_status\":",
                 static_cast<unsigned int>(nation->scenarioInitFlag),
                 static_cast<unsigned int>(nation->field904));
      json += row;
      AppendSignedByteArray(json, nation->pendingActionStatus.byAction, 0x0d);
      json += ",\"pending_action_payload_by_action\":";
      AppendShortArray(json, nation->field8d6, 0x0d);
      row.Format(",\"diplomacy_budget_base\":%d,\"escalation_counter\":%d,"
                 "\"pending_commitment_cost\":%d,\"pressure_counter\":%d,"
                 "\"aid_allocation_total\":%d,\"colony_boycott_flags\":",
                 nation->diplomacyBudgetBase, static_cast<int>(nation->escalationCounter),
                 nation->pendingCommitmentCost, static_cast<int>(nation->pressureCounter),
                 nation->aidAllocationTotal);
      json += row;
      AppendUnsignedByteArray(json, nation->colonyBoycottFlags, kNationSlotCount);
      // gameScoreRows930 is an on-demand derived display cache. It is not initialized until the
      // score screen or turn-end calculation requests it, so serializing it would expose heap
      // history rather than game state.
      row.Format(",\"military_expenses\":%d}", nation->militaryExpenses960);
      json += row;
    }
    json += "}";
  }
  json += "]}";
  return json;
}

CString CaptureEconomy() {
  CString json("{\"cities\":[");
  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    TCity* city = nation != 0 ? nation->city : 0;
    CString row;
    row.Format("%s{\"nation\":%d,\"present\":%s", slot == 0 ? "" : ",", slot,
               city != 0 ? "true" : "false");
    json += row;
    if (city == 0) {
      json += "}";
      continue;
    }

    row.Format(",\"power_plant_upgrade_queued\":%u,\"food_substitution_count\":%d,"
               "\"starvation_population_loss\":%d,\"serialized_state\":%d,"
               "\"phase_counter\":%d,\"metrics_0e\":",
               static_cast<unsigned int>(city->powerPlantUpgradeQueuedFlag04),
               static_cast<int>(city->foodSubstitutionCount06),
               static_cast<int>(city->starvationPopulationLoss08),
               static_cast<int>(city->serializedState0a),
               static_cast<int>(city->cityPhaseCounter0c));
    json += row;
    AppendShortArray(json, city->cityMetricsBlock0E, 0x1e);
    json += ",\"metrics_4a\":";
    AppendShortArray(json, city->cityMetricsBlock4A, 9);
    json += ",\"order_count_by_type\":";
    AppendShortArray(json, city->orderCountByType5c, kIndustryActionSlotCount);
    row.Format(",\"rolling_item_production_score\":%d,\"low_production\":%u,"
               "\"low_stock\":%u,\"reserved_by_type\":",
               city->rollingItemProductionScore78,
               static_cast<unsigned int>(city->lowProductionFlag7c),
               static_cast<unsigned int>(city->lowStockFlag7d));
    json += row;
    AppendShortArray(json, city->reservedByType7e, kResourceKindCount);
    row.Format(",\"home_town_tile\":%d,\"power_available\":%d,\"stock_by_type\":",
               city->homeTownMarkerB0 != 0 ? static_cast<int>(city->homeTownMarkerB0->tileIndex)
                                           : -1,
               static_cast<int>(city->powerAvailableB4));
    json += row;
    AppendShortArray(json, &city->cityStockCottonB6, kResourceKindCount);
    json += ",\"production_orders\":";
    AppendShortArray(json, city->productionOrderTable1dc, 0x10);
    json += ",\"production_accum\":";
    AppendShortArray(json, city->productionAccum1fc, 0x10);
    json += ",\"production_flags\":";
    AppendUnsignedByteArray(json, city->productionFlags21c, 0x10);
    json += ",\"production_current\":";
    AppendShortArray(json, city->production22c, 0x10);
    json += ",\"production_progress\":";
    AppendShortArray(json, city->production24c, 0x10);
    row.Format(",\"population_growth_penalty_ticks\":%d,\"unmet_resource_retries\":",
               static_cast<int>(city->populationGrowthPenaltyTicks26c));
    json += row;
    AppendShortArray(json, city->unmetResourceRetryCount278, kResourceKindCount);
    json += ",\"consumed_production_input_by_type\":";
    AppendShortArray(json, city->consumedProductionInputByType2a6, kResourceKindCount);
    json += ",\"population\":";

    TPopulationMgr* population = city->productionSummary1d8;
    if (population == 0) {
      json += "null";
    } else {
      row.Format("{\"count\":%d,\"count_float_bits\":%u,\"strength\":%d,"
                 "\"extra\":%d,\"phase_value\":%d,\"baseline_labor\":",
                 static_cast<int>(population->populationCount08),
                 FloatBits(population->populationCountFloat0c),
                 static_cast<int>(population->strength), static_cast<int>(population->extraAt1e),
                 static_cast<int>(population->fieldAt20));
      json += row;
      AppendLaborPool(json, population->baselineSlots10);
      json += ",\"production_labor\":";
      AppendLaborPool(json, population->productionSlots14);
      json += ",\"pending_labor_delta\":";
      AppendLaborPool(json, population->pendingDeltaSlots18);
      json += ",\"predicted_need_by_resource\":";
      AppendShortArray(json, population->predictedNeedByResource22, kResourceKindCount);
      json += "}";
    }
    json += "}";
  }
  json += "]}";
  return json;
}

int SnapshotShipIndex(const TShip* target) {
  int index = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship == target) {
      return index;
    }
    ++index;
  }
  return -1;
}

int SnapshotTaskForceIndex(const TTaskForce* target) {
  if (g_pNavyOrderManager == 0) {
    return -1;
  }
  int index = 0;
  for (TTaskForce* force = g_pNavyOrderManager->orderQueueHead; force != 0;
       force = force->nextForce) {
    if (force == target) {
      return index;
    }
    ++index;
  }
  return -1;
}

int SnapshotZoneIndex(const TZone* zone) {
  return zone != 0 ? static_cast<int>(zone->contextOrdinal14) : -1;
}

void AppendArmyMission(CString& json, TArmyMission* mission) {
  CString row;
  row.Format("{\"present_location\":%d,\"required_equipage_bits\":[%u,%u,%u,%u,%u],"
             "\"units\":[",
             static_cast<int>(mission->presentLocation14),
             FloatBits(mission->requiredEquipageByClass[0]),
             FloatBits(mission->requiredEquipageByClass[1]),
             FloatBits(mission->requiredEquipageByClass[2]),
             FloatBits(mission->requiredEquipageByClass[3]),
             FloatBits(mission->requiredEquipageByClass[4]));
  json += row;
  int unitOrdinal = 1;
  int unitCount = mission->orderListAt18 != 0 ? mission->orderListAt18->GetCount() : 0;
  for (; unitOrdinal <= unitCount; ++unitOrdinal) {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(mission->orderListAt18->GetEntryByOrdinal(unitOrdinal));
    row.Format("%s%d", unitOrdinal == 1 ? "" : ",", unit != 0 ? unit->persistentUnitId20 : -1);
    json += row;
  }
  json += "]}";
}

void AppendNavyMission(CString& json, TNavyMission* mission) {
  CString row;
  row.Format(
      "{\"target_zone\":%d,\"resolved_port_zone\":%d,\"selected_ship\":%d,"
      "\"task_force\":%d,\"state\":%d,"
      "\"required_equipage_bits\":[%u,%u,%u,%u],\"ships\":[",
      SnapshotZoneIndex(mission->missionTargetZone), SnapshotZoneIndex(mission->resolvedPortZone),
      SnapshotShipIndex(mission->selectedOrder1c), SnapshotTaskForceIndex(mission->taskForce20),
      mission->navyState28, FloatBits(mission->requiredShipEquipageByCategory[0]),
      FloatBits(mission->requiredShipEquipageByCategory[1]),
      FloatBits(mission->requiredShipEquipageByCategory[2]),
      FloatBits(mission->requiredShipEquipageByCategory[3]));
  json += row;
  int childIndex = 0;
  for (TMapOrderChildLinkNode* link = mission->orderList24; link != 0; link = link->next) {
    row.Format("%s[%d,%u]", childIndex == 0 ? "" : ",",
               SnapshotShipIndex(static_cast<TShip*>(link->payload)),
               static_cast<unsigned int>(link->active));
    json += row;
    ++childIndex;
  }
  json += "]}";
}

CString CaptureMissions() {
  CString json("{\"records\":[");
  bool first = true;
  int missionIndex = 0;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    TSortedList* queue = static_cast<TAutoGreatPower*>(nation)->missionQueue;
    int missionCount = queue != 0 ? queue->GetCount() : 0;
    for (int queueOrdinal = 1; queueOrdinal <= missionCount; ++queueOrdinal) {
      TMission* mission = static_cast<TMission*>(queue->GetEntryByOrdinal(queueOrdinal));
      if (mission == 0) {
        continue;
      }
      CRuntimeClass* runtimeClass = mission->GetRuntimeClass();
      CString row;
      row.Format("%s{\"index\":%d,\"nation\":%d,\"queue_index\":%d,\"class\":", first ? "" : ",",
                 missionIndex, nationSlot, queueOrdinal - 1);
      json += row;
      RuntimeJson::AppendString(json,
                                runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown");
      // TMission's retail constructor leaves flag10 uninitialized until Hold assigns it. It is
      // therefore allocator history for fresh missions, not canonical state.
      row.Format(",\"source_nation\":%d,\"path_marker\":%d,\"state\":%u,"
                 "\"importance_bits\":%u,\"marker\":%u,\"army\":",
                 static_cast<int>(mission->nationId04), static_cast<int>(mission->pathMarker06),
                 static_cast<unsigned int>(mission->state08), FloatBits(mission->importanceScore0c),
                 static_cast<unsigned int>(mission->marker11));
      json += row;
      if (mission->IsKindOf(RUNTIME_CLASS(TArmyMission))) {
        AppendArmyMission(json, static_cast<TArmyMission*>(mission));
      } else {
        json += "null";
      }
      json += ",\"navy\":";
      if (mission->IsKindOf(RUNTIME_CLASS(TNavyMission))) {
        AppendNavyMission(json, static_cast<TNavyMission*>(mission));
      } else {
        json += "null";
      }
      json += ",\"attack\":";
      if (mission->IsKindOf(RUNTIME_CLASS(TAttackProvinceMission))) {
        TAttackProvinceMission* attack = static_cast<TAttackProvinceMission*>(mission);
        row.Format("{\"target_province\":%d,\"amassing_province\":%d}",
                   static_cast<int>(attack->targetProvince30),
                   static_cast<int>(attack->amassingProvince32));
        json += row;
      } else {
        json += "null";
      }
      json += ",\"beachhead\":";
      if (mission->IsKindOf(RUNTIME_CLASS(TInvadeMission)) &&
          static_cast<TInvadeMission*>(mission)->beachhead34 != 0) {
        AppendNavyMission(json, static_cast<TInvadeMission*>(mission)->beachhead34);
      } else {
        json += "null";
      }
      json += ",\"blockade_port_zone\":";
      if (mission->IsKindOf(RUNTIME_CLASS(TBlockadePortMission))) {
        row.Format("%d", SnapshotZoneIndex(
                             static_cast<TBlockadePortMission*>(mission)->portZoneContext3c));
        json += row;
      } else {
        json += "null";
      }
      json += "}";
      first = false;
      ++missionIndex;
    }
  }
  json += "]}";
  return json;
}

void AppendRelationshipQueue(CString& json, TSortedByRelationshipList* queue) {
  json += "[";
  int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    CString row;
    row.Format("%s[%d,%d]", ordinal == 1 ? "" : ",", static_cast<int>(record[0]),
               static_cast<int>(record[1]));
    json += row;
  }
  json += "]";
}

CString CapturePending() {
  CString json;
  json.Format("{\"turn_flow_status_flags\":%u,\"nations\":[",
              g_pSimMgr != 0 ? g_pSimMgr->turnFlowStatusFlags : 0);
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    CString row;
    row.Format("%s{\"nation\":%d,\"turn_events\":", nationSlot == 0 ? "" : ",", nationSlot);
    json += row;
    AppendRelationshipQueue(json, nation != 0 ? nation->turnEventQueue : 0);
    json += ",\"proposals\":";
    AppendRelationshipQueue(json, nation != 0 ? nation->proposalQueue : 0);
    json += ",\"turn_summary\":[";
    int summaryCount =
        nation != 0 && nation->turnSummaryQueue != 0 ? nation->turnSummaryQueue->GetSize() : 0;
    for (int summaryOrdinal = 1; summaryOrdinal <= summaryCount; ++summaryOrdinal) {
      TurnOrderDispatchPacket* packet = static_cast<TurnOrderDispatchPacket*>(
          nation->turnSummaryQueue->GetPtrListEntryByOneBasedIndex(summaryOrdinal));
      row.Format("%s[%d,%d,%d,%d]", summaryOrdinal == 1 ? "" : ",",
                 static_cast<int>(packet->turnTick), static_cast<int>(packet->orderKind),
                 static_cast<int>(packet->payload), static_cast<int>(packet->flags));
      json += row;
    }
    json += "],\"turn_start_events\":[";
    int eventCount =
        nation != 0 && nation->missionNodeQueue != 0 ? nation->missionNodeQueue->GetCount() : 0;
    for (int eventOrdinal = 1; eventOrdinal <= eventCount; ++eventOrdinal) {
      TTurnStartEvent* event =
          static_cast<TTurnStartEvent*>(nation->missionNodeQueue->GetEntryByOrdinal(eventOrdinal));
      CRuntimeClass* runtimeClass = event != 0 ? event->GetRuntimeClass() : 0;
      row.Format("%s{\"class\":", eventOrdinal == 1 ? "" : ",");
      json += row;
      RuntimeJson::AppendString(json,
                                runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown");
      row.Format(",\"tag\":%d,\"land_sale\":", event != 0 ? event->eventTag04 : 0);
      json += row;
      if (event != 0 && event->IsKindOf(RUNTIME_CLASS(TLandSaleEvent))) {
        TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
        row.Format("[%d,%d]", static_cast<int>(landSale->tileIndex08),
                   static_cast<int>(landSale->nationCode0a));
        json += row;
      } else {
        json += "null";
      }
      json += "}";
    }
    json += "]}";
  }
  json += "],\"war_transitions\":[";
  TSortedPtrList* warQueue = g_pDiplomacyTurnStateManager != 0
                                 ? g_pDiplomacyTurnStateManager->pendingWarTransitionQueue
                                 : 0;
  int warCount = warQueue != 0 ? warQueue->GetSize() : 0;
  for (int warOrdinal = 1; warOrdinal <= warCount; ++warOrdinal) {
    short* pair = static_cast<short*>(warQueue->GetPtrListEntryByOneBasedIndex(warOrdinal));
    CString row;
    row.Format("%s[%d,%d]", warOrdinal == 1 ? "" : ",", static_cast<int>(pair[0]),
               static_cast<int>(pair[1]));
    json += row;
  }
  json += "]}";
  return json;
}

CString CaptureMilitary() {
  CString json("{\"units\":[");
  bool first = true;
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    CIterator cursor(country->militaryUnitList44);
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    int rosterIndex = 0;
    while (cursor.More() != 0) {
      CString row;
      row.Format("%s{\"nation\":%d,\"roster_index\":%d,\"persistent_id\":%d,"
                 "\"unit_type\":%d,\"stationed_province\":%d,\"order\":%d,"
                 "\"order_target\":%d,\"owner_nation\":%d,\"roster_id\":%d,"
                 "\"registered\":%u,\"order_target_tiles\":",
                 first ? "" : ",", nationSlot, rosterIndex, unit->persistentUnitId20,
                 static_cast<int>(unit->orderType), static_cast<int>(unit->tileIndex06),
                 static_cast<int>(unit->unitOrder), static_cast<int>(unit->orderTargetIndex0C),
                 static_cast<int>(unit->ownerNationSlot18), static_cast<int>(unit->unitRosterId1A),
                 static_cast<unsigned int>(unit->militaryRegistrationFlag1C));
      json += row;
      AppendShortArray(json, unit->orderTargetTiles28, 3);
      json += ",\"order_target_mirrors\":";
      AppendShortArray(json, unit->orderTargetTilesMirror2E, 3);
      json += ",\"name\":";
      RuntimeJson::AppendString(json, static_cast<LPCSTR>(unit->name24));
      row.Format(",\"strength\":%d,\"era\":%d,\"experience\":%d,\"battle_flags\":%d}",
                 static_cast<int>(unit->strength34), static_cast<int>(unit->eraIndex36),
                 static_cast<int>(unit->experiencePercent38),
                 static_cast<int>(unit->battleStateFlags3A));
      json += row;
      first = false;
      ++rosterIndex;
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }

  json += "],\"civilians\":[";
  first = true;
  for (int civilianNationSlot = 0; civilianNationSlot < kMajorNationCount; ++civilianNationSlot) {
    TGreatPower* nation = g_apNationStates[civilianNationSlot];
    int civilianCount =
        nation != 0 && nation->trackedObjectList != 0 ? nation->trackedObjectList->GetCount() : 0;
    for (int ordinal = 1; ordinal <= civilianCount; ++ordinal) {
      TCivUnit* unit =
          static_cast<TCivUnit*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      CString row;
      row.Format("%s{\"nation\":%d,\"roster_index\":%d,\"persistent_id\":%d,"
                 "\"unit_type\":%d,\"tile\":%d,\"order\":%d,\"order_target\":%d,"
                 "\"owner_nation\":%d,\"roster_id\":%d,\"registered\":%u,"
                 "\"remaining_turns\":%d}",
                 first ? "" : ",", civilianNationSlot, ordinal - 1, unit->persistentUnitId20,
                 static_cast<int>(unit->orderType), static_cast<int>(unit->tileIndex06),
                 static_cast<int>(unit->unitOrder), static_cast<int>(unit->orderTargetIndex0C),
                 static_cast<int>(unit->ownerNationSlot18), static_cast<int>(unit->unitRosterId1A),
                 static_cast<unsigned int>(unit->militaryRegistrationFlag1C),
                 static_cast<int>(unit->remainingTurns24));
      json += row;
      first = false;
    }
  }

  json += "],\"ships\":[";
  int shipIndex = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    CString row;
    row.Format("%s{\"index\":%d,\"type\":%d,\"location\":%d,\"task_force\":%d,"
               "\"aggression\":%d,\"nation\":%d,\"name\":",
               shipIndex == 0 ? "" : ",", shipIndex, static_cast<int>(ship->type),
               ship->location != 0 ? static_cast<int>(ship->location->contextOrdinal14) : -1,
               SnapshotTaskForceIndex(ship->taskForce), ship->aggression,
               static_cast<int>(ship->nation));
    json += row;
    RuntimeJson::AppendString(json, static_cast<LPCSTR>(ship->name));
    row.Format(",\"strength\":%d,\"experience\":%d,\"selection\":%d}",
               static_cast<int>(ship->strength), static_cast<int>(ship->experience),
               ship->selection);
    json += row;
    ++shipIndex;
  }

  json += "],\"task_forces\":[";
  int forceIndex = 0;
  TTaskForce* force = g_pNavyOrderManager != 0 ? g_pNavyOrderManager->orderQueueHead : 0;
  for (; force != 0; force = force->nextForce) {
    int targetKind = force->shipOrders == 5 ? 1 : 0;
    int targetIndex = -1;
    if (force->target != 0) {
      targetIndex = targetKind != 0
                        ? static_cast<int>(static_cast<Province*>(force->target)->GetIndex())
                        : static_cast<int>(static_cast<TZone*>(force->target)->contextOrdinal14);
    }
    CString row;
    row.Format("%s{\"index\":%d,\"aggression\":%d,\"order\":%d,\"target_kind\":%d,"
               "\"target\":%d,\"location\":%d,\"nation\":%d,\"ship_counts\":",
               forceIndex == 0 ? "" : ",", forceIndex, force->aggression, force->shipOrders,
               targetKind, targetIndex,
               force->location != 0 ? static_cast<int>(force->location->contextOrdinal14) : -1,
               static_cast<int>(force->nation));
    json += row;
    AppendShortArray(json, force->shipCountsByToolbarSlot, 4);
    // Both retail constructors leave defeated uninitialized; RechargeAll establishes it before
    // battle processing. A freshly submitted order therefore cannot expose this allocator byte.
    row.Format(",\"ingot_tile\":%d,\"flagship\":%d,\"ships\":[",
               static_cast<int>(force->ingotTileIndex), SnapshotShipIndex(force->flagship));
    json += row;
    int childIndex = 0;
    for (TMapOrderChildLinkNode* link = force->shipList; link != 0; link = link->next) {
      row.Format("%s[%d,%u]", childIndex == 0 ? "" : ",",
                 SnapshotShipIndex(static_cast<TShip*>(link->payload)),
                 static_cast<unsigned int>(link->active));
      json += row;
      ++childIndex;
    }
    json += "]}";
    ++forceIndex;
  }
  json += "]}";
  return json;
}

} // namespace

bool BuildRuntimeGameSnapshot(const RuntimeRun& run, CString& snapshotJson) {
  if (g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 || g_pSimMgr == 0) {
    return false;
  }

  CString metadata(CaptureMetadata(run));
  CString rng(CaptureRng(run));
  CString world(CaptureWorld());
  CString nations(CaptureNations());
  CString economy(CaptureEconomy());
  CString military(CaptureMilitary());
  CString missions(CaptureMissions());
  CString pending(CapturePending());
  CString state(metadata);
  state += rng;
  state += world;
  state += nations;
  state += economy;
  state += military;
  state += missions;
  state += pending;
  CString metadataHash(RuntimeHashText(metadata));
  CString rngHash(RuntimeHashText(rng));
  CString worldHash(RuntimeHashText(world));
  CString nationsHash(RuntimeHashText(nations));
  CString economyHash(RuntimeHashText(economy));
  CString militaryHash(RuntimeHashText(military));
  CString missionsHash(RuntimeHashText(missions));
  CString pendingHash(RuntimeHashText(pending));
  CString stateHash(RuntimeHashText(state));

  snapshotJson.Format(
      "{\"schema\":\"imperialism.game_snapshot.v1\","
      "\"sections\":[\"metadata\",\"rng\",\"world\",\"nations\",\"economy\","
      "\"military\",\"missions\",\"pending\"],"
      "\"hashes\":{\"metadata\":\"%s\",\"rng\":\"%s\",\"world\":\"%s\","
      "\"nations\":\"%s\",\"economy\":\"%s\",\"military\":\"%s\","
      "\"missions\":\"%s\",\"pending\":\"%s\","
      "\"state\":\"%s\"},"
      "\"metadata\":%s,\"rng\":%s,\"world\":%s,\"nations\":%s,"
      "\"economy\":%s,\"military\":%s,\"missions\":%s,\"pending\":%s}",
      static_cast<LPCSTR>(metadataHash), static_cast<LPCSTR>(rngHash),
      static_cast<LPCSTR>(worldHash), static_cast<LPCSTR>(nationsHash),
      static_cast<LPCSTR>(economyHash), static_cast<LPCSTR>(militaryHash),
      static_cast<LPCSTR>(missionsHash), static_cast<LPCSTR>(pendingHash),
      static_cast<LPCSTR>(stateHash), static_cast<LPCSTR>(metadata), static_cast<LPCSTR>(rng),
      static_cast<LPCSTR>(world), static_cast<LPCSTR>(nations), static_cast<LPCSTR>(economy),
      static_cast<LPCSTR>(military), static_cast<LPCSTR>(missions), static_cast<LPCSTR>(pending));
  return true;
}

void CaptureRuntimeGameSnapshot(RuntimeRun& run) {
  if (!run.CapturesSnapshot(kRuntimeSnapshotGame) || !run.GameSnapshotJson().IsEmpty()) {
    return;
  }
  BuildRuntimeGameSnapshot(run, run.GameSnapshotJson());
}
