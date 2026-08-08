#include "RuntimeGameStateCapture.h"

#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/debug/TLaborPool.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/nation_globals.h"
#include "game/map/TBeachheadMission.h"
#include "game/map/TBlockadePortMission.h"
#include "game/map/TControlSeaZoneMission.h"
#include "game/map/TEscortMission.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMission.h"
#include "game/map/TNavyMission.h"
#include "game/map/TScatteredShipsMission.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/military/TArmyMission.h"
#include "game/military/TAttackProvinceMission.h"
#include "game/military/TCivUnit.h"
#include "game/military/TDefendProvinceMission.h"
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

const char* const kPendingActionNames[0x0d] = {"navy_growth_reward",
                                               "army_growth_reward",
                                               "overseas_developer_reward",
                                               "village_development",
                                               "town_development",
                                               "shipyard_ironworking_upgrade",
                                               "conquered_capital_armory_upgrade",
                                               "university_expansion",
                                               "railyard_expansion",
                                               "annexed_great_power_capital_expansion",
                                               "colony_monument_merchant_capacity",
                                               "council_lead_monument",
                                               "conquest_monument_armory"};

JSON_Value* NewObject(JSON_Object*& object) {
  object = 0;
  JSON_Value* value = json_value_init_object();
  if (value == 0) {
    return 0;
  }
  object = json_value_get_object(value);
  if (object == 0) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* NewArray(JSON_Array*& array) {
  array = 0;
  JSON_Value* value = json_value_init_array();
  if (value == 0) {
    return 0;
  }
  array = json_value_get_array(value);
  if (array == 0) {
    json_value_free(value);
    return 0;
  }
  return value;
}

bool SetValue(JSON_Object* object, const char* name, JSON_Value* value) {
  if (object == 0 || value == 0 || json_object_set_value(object, name, value) != JSONSuccess) {
    json_value_free(value);
    return false;
  }
  return true;
}

bool AppendValue(JSON_Array* array, JSON_Value* value) {
  if (array == 0 || value == 0 || json_array_append_value(array, value) != JSONSuccess) {
    json_value_free(value);
    return false;
  }
  return true;
}

bool SetOptionalNumber(JSON_Object* object, const char* name, int value) {
  return value < 0 ? json_object_set_null(object, name) == JSONSuccess
                   : json_object_set_number(object, name, value) == JSONSuccess;
}

JSON_Value* CaptureShortArray(const short* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < count; ++index) {
    if (json_array_append_number(array, static_cast<int>(values[index])) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureIntArray(const int* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < count; ++index) {
    if (json_array_append_number(array, values[index]) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureUnsignedByteArray(const unsigned char* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < count; ++index) {
    if (json_array_append_number(array, static_cast<unsigned int>(values[index])) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

unsigned int FloatBits(float value) {
  unsigned int bits = 0;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
}

JSON_Value* CaptureResourceTable(const short* values) {
  static const char* const kResourceNames[kResourceKindCount] = {
      "cotton", "wool",   "timber", "coal",  "iron",      "horses",   "oil",       "food",
      "fabric", "lumber", "paper",  "steel", "fuel",      "clothing", "furniture", "hardware",
      "arms",   "grain",  "fruit",  "fish",  "livestock", "gems",     "gold"};
  JSON_Object* table = 0;
  JSON_Value* value = NewObject(table);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < kResourceKindCount; ++index) {
    if (json_object_set_number(table, kResourceNames[index], static_cast<int>(values[index])) !=
        JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CapturePendingActionStatus(const signed char* values) {
  JSON_Object* table = 0;
  JSON_Value* value = NewObject(table);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < 0x0d; ++index) {
    if (json_object_set_number(table, kPendingActionNames[index],
                               static_cast<int>(values[index])) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CapturePendingActionPayloads(const short* values) {
  JSON_Object* table = 0;
  JSON_Value* value = NewObject(table);
  if (value == 0) {
    return 0;
  }
  for (int index = 0; index < 0x0d; ++index) {
    if (json_object_set_number(table, kPendingActionNames[index],
                               static_cast<int>(values[index])) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureLaborPool(const TLaborPool* pool) {
  if (pool == 0) {
    return json_value_init_null();
  }
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0) {
    return 0;
  }
  if (json_object_set_number(object, "low", static_cast<int>(pool->lowSkillCount04)) !=
          JSONSuccess ||
      json_object_set_number(object, "medium", static_cast<int>(pool->mediumSkillCount06)) !=
          JSONSuccess ||
      json_object_set_number(object, "high", static_cast<int>(pool->highSkillCount08)) !=
          JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

unsigned int RuntimeCrtRandState() {
  struct CrtThreadDataPrefix {
    unsigned char prefix00[0x14];
    unsigned int randState14;
  };
  CrtThreadDataPrefix* threadData = static_cast<CrtThreadDataPrefix*>(_getptd());
  return threadData != 0 ? threadData->randState14 : 0;
}

JSON_Value* CaptureTurn(const RuntimeRun& run) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0) {
    return 0;
  }
  if (json_object_set_number(object, "scenario_map_index_plus_one",
                             g_pSimMgr != 0 ? g_pSimMgr->scenarioMapIndexPlusOne : 0) !=
          JSONSuccess ||
      json_object_set_number(object, "economic_turn",
                             g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1) != JSONSuccess ||
      json_object_set_number(object, "phase_code",
                             g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1) != JSONSuccess ||
      json_object_set_number(object, "difficulty",
                             g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1) != JSONSuccess ||
      json_object_set_number(object, "active_nation",
                             g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1) != JSONSuccess ||
      json_object_set_number(object, "selected_nation", run.SelectedNationSlot()) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureRng() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0) {
    return 0;
  }
  if (json_object_set_number(object, "crt_rand", RuntimeCrtRandState()) != JSONSuccess ||
      json_object_set_number(object, "map_generation", g_mapGenLcgState_006a38e8) != JSONSuccess ||
      json_object_set_number(object, "zone_status", g_zoneStatusCodePrngSeed_006a5aec) !=
          JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureWorld() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* tiles = 0;
  JSON_Value* tilesValue = NewArray(tiles);
  if (value == 0 || tilesValue == 0) {
    json_value_free(tilesValue);
    json_value_free(value);
    return 0;
  }
  if (json_object_set_number(object, "width", 108) != JSONSuccess ||
      json_object_set_number(object, "height", 60) != JSONSuccess ||
      json_object_set_boolean(object, "wraps_horizontally",
                              g_pGlobalMapState->hexNeighborWrapHorizontally == 0) != JSONSuccess) {
    json_value_free(tilesValue);
    json_value_free(value);
    return 0;
  }
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    JSON_Object* tileObject = 0;
    JSON_Value* tileValue = NewObject(tileObject);
    JSON_Array* edgeResources = 0;
    JSON_Value* edgeResourcesValue = NewArray(edgeResources);
    if (tileValue == 0 || edgeResourcesValue == 0 ||
        json_object_set_number(tileObject, "terrain_kind",
                               static_cast<int>(tile.GetTerrainKind())) != JSONSuccess ||
        !SetOptionalNumber(tileObject, "owner_nation", static_cast<int>(tile.ownerNationTag04)) ||
        !SetOptionalNumber(tileObject, "former_owner_nation",
                           static_cast<int>(tile.formerOwnerNationTag03)) ||
        !SetOptionalNumber(tileObject, "province", static_cast<int>(tile.cityRecordIndex)) ||
        json_object_set_number(tileObject, "development_classes",
                               static_cast<int>(tile.developmentClassNibbles0c)) != JSONSuccess ||
        (tile.resourceTypeByEdge[0] < 0
             ? json_array_append_null(edgeResources)
             : json_array_append_number(
                   edgeResources, static_cast<int>(tile.resourceTypeByEdge[0]))) != JSONSuccess ||
        (tile.resourceTypeByEdge[1] < 0
             ? json_array_append_null(edgeResources)
             : json_array_append_number(
                   edgeResources, static_cast<int>(tile.resourceTypeByEdge[1]))) != JSONSuccess ||
        !SetValue(tileObject, "edge_resources", edgeResourcesValue) ||
        json_object_set_number(tileObject, "rail_flags",
                               static_cast<unsigned int>(tile.railFlags17)) != JSONSuccess ||
        json_object_set_number(tileObject, "action_state",
                               static_cast<int>(tile.tileActionState16)) != JSONSuccess ||
        json_object_set_number(tileObject, "active_flags",
                               static_cast<unsigned int>(tile.activeFlags1c)) != JSONSuccess ||
        !AppendValue(tiles, tileValue)) {
      if (edgeResourcesValue != 0 && json_value_get_parent(edgeResourcesValue) == 0) {
        json_value_free(edgeResourcesValue);
      }
      if (tileValue != 0 && json_value_get_parent(tileValue) == 0) {
        json_value_free(tileValue);
      }
      json_value_free(tilesValue);
      json_value_free(value);
      return 0;
    }
  }
  if (!SetValue(object, "tiles", tilesValue)) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureMajorNation(TGreatPower* nation) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* capacities = 0;
  JSON_Value* capacitiesValue = NewArray(capacities);
  if (value == 0 || capacitiesValue == 0) {
    json_value_free(capacitiesValue);
    json_value_free(value);
    return 0;
  }
  if (json_array_append_number(capacities, static_cast<int>(nation->availableMerchantCapacity)) !=
          JSONSuccess ||
      json_array_append_number(capacities, static_cast<int>(nation->merchantCapacity)) !=
          JSONSuccess ||
      json_array_append_number(capacities, static_cast<int>(nation->transportCapacity)) !=
          JSONSuccess ||
      json_array_append_number(capacities, static_cast<int>(nation->reservedTransportCapacity)) !=
          JSONSuccess ||
      json_object_set_string(object, "kind", "major") != JSONSuccess ||
      json_object_set_boolean(object, "diplomacy_eligible", nation->diplomacyEligibilityA0 != 0) !=
          JSONSuccess ||
      !SetValue(object, "capacities", capacitiesValue) ||
      json_object_set_number(object, "grant_total_cost", nation->grantTotalCost) != JSONSuccess ||
      json_object_set_number(object, "unfilled_trade_offer_count",
                             static_cast<int>(nation->unfilledTradeOfferCount)) != JSONSuccess ||
      !SetValue(object, "diplomacy_policy_by_nation",
                CaptureShortArray(nation->diplomacyPolicyByNation, kNationSlotCount)) ||
      !SetValue(object, "diplomacy_grant_by_nation",
                CaptureShortArray(nation->diplomacyGrantByNation, kNationSlotCount)) ||
      !SetValue(object, "need_current_by_type", CaptureResourceTable(nation->needCurrentByType)) ||
      !SetValue(object, "need_target_by_type", CaptureResourceTable(nation->needTargetByType)) ||
      !SetValue(object, "relation_delta_current",
                CaptureResourceTable(nation->relationDeltaCurrent)) ||
      !SetValue(object, "purchased_items_by_resource",
                CaptureResourceTable(nation->purchasedItemsByResource)) ||
      !SetValue(object, "item_potentials", CaptureResourceTable(nation->itemPotentials)) ||
      !SetValue(object, "unfilled_trade_turns_by_resource",
                CaptureResourceTable(nation->unfilledTradeTurnCountsByResource)) ||
      !SetValue(object, "transported_items_by_resource",
                CaptureResourceTable(nation->transportedItemsByResource)) ||
      !SetValue(object, "remembered_trade_offers_by_resource",
                CaptureResourceTable(nation->rememberedTradeOffersByResource)) ||
      !SetValue(object, "aid_allocation_matrix",
                CaptureIntArray(nation->aidAllocationMatrix, 0x170)) ||
      json_object_set_number(object, "budget_pool_base", nation->budgetPoolBase) != JSONSuccess ||
      json_object_set_number(object, "budget_pool_delta", nation->budgetPoolDelta) != JSONSuccess ||
      json_object_set_number(object, "special_resource_trade_balance", nation->field910) !=
          JSONSuccess ||
      !SetValue(object, "candidate_nation_flags",
                CaptureUnsignedByteArray(nation->candidateNationFlags, kNationSlotCount)) ||
      json_object_set_boolean(object, "scenario_initialized", nation->scenarioInitFlag != 0) !=
          JSONSuccess ||
      json_object_set_boolean(object, "turn_finished", nation->field904 != 0) != JSONSuccess ||
      !SetValue(object, "pending_action_status",
                CapturePendingActionStatus(nation->pendingActionStatus.byAction)) ||
      !SetValue(object, "pending_action_payload_by_action",
                CapturePendingActionPayloads(nation->field8d6)) ||
      json_object_set_number(object, "diplomacy_budget_base", nation->diplomacyBudgetBase) !=
          JSONSuccess ||
      json_object_set_number(object, "escalation_counter",
                             static_cast<int>(nation->escalationCounter)) != JSONSuccess ||
      json_object_set_number(object, "pending_commitment_cost", nation->pendingCommitmentCost) !=
          JSONSuccess ||
      json_object_set_number(object, "pressure_counter",
                             static_cast<int>(nation->pressureCounter)) != JSONSuccess ||
      json_object_set_number(object, "aid_allocation_total", nation->aidAllocationTotal) !=
          JSONSuccess ||
      !SetValue(object, "colony_boycott_flags",
                CaptureUnsignedByteArray(nation->colonyBoycottFlags, kNationSlotCount)) ||
      json_object_set_number(object, "military_expenses", nation->militaryExpenses960) !=
          JSONSuccess) {
    if (capacitiesValue != 0 && json_value_get_parent(capacitiesValue) == 0) {
      json_value_free(capacitiesValue);
    }
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureNation(int slot) {
  TCountry* country = g_apTerrainTypeDescriptorTable[slot];
  if (country == 0) {
    return json_value_init_null();
  }

  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Object* common = 0;
  JSON_Value* commonValue = NewObject(common);
  if (value == 0 || commonValue == 0 || json_object_set_number(object, "id", slot) != JSONSuccess ||
      json_object_set_number(common, "encoded_nation_slot",
                             static_cast<int>(country->encodedNationSlot)) != JSONSuccess ||
      json_object_set_number(common, "owner_nation",
                             static_cast<int>(country->DecodeOwnerNationSlot())) != JSONSuccess ||
      json_object_set_number(common, "treasury", country->treasuryValue10) != JSONSuccess ||
      json_object_set_number(common, "home_tile", country->homeTileIndex) != JSONSuccess ||
      !SetValue(common, "need_level_by_nation",
                CaptureShortArray(country->needLevelByNation, kNationSlotCount)) ||
      !SetValue(object, "common", commonValue)) {
    if (commonValue != 0 && json_value_get_parent(commonValue) == 0) {
      json_value_free(commonValue);
    }
    json_value_free(value);
    return 0;
  }

  JSON_Value* dataValue = 0;
  if (slot < kMajorNationCount) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0) {
      json_value_free(value);
      return 0;
    }
    dataValue = CaptureMajorNation(nation);
  } else {
    JSON_Object* data = 0;
    dataValue = NewObject(data);
    if (dataValue != 0 && json_object_set_string(data, "kind", "minor") != JSONSuccess) {
      json_value_free(dataValue);
      dataValue = 0;
    }
  }
  if (!SetValue(object, "data", dataValue)) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureNations() {
  JSON_Array* nations = 0;
  JSON_Value* value = NewArray(nations);
  if (value == 0) {
    return 0;
  }
  for (int slot = 0; slot < kNationSlotCount; ++slot) {
    if (!AppendValue(nations, CaptureNation(slot))) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CapturePopulation(const TPopulationMgr* population) {
  if (population == 0) {
    return 0;
  }
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0 ||
      json_object_set_number(object, "count", static_cast<int>(population->populationCount08)) !=
          JSONSuccess ||
      json_object_set_number(object, "count_float_bits",
                             FloatBits(population->populationCountFloat0c)) != JSONSuccess ||
      json_object_set_number(object, "strength", static_cast<int>(population->strength)) !=
          JSONSuccess ||
      json_object_set_number(object, "extra", static_cast<int>(population->extraAt1e)) !=
          JSONSuccess ||
      json_object_set_number(object, "phase_value", static_cast<int>(population->fieldAt20)) !=
          JSONSuccess ||
      !SetValue(object, "baseline_labor", CaptureLaborPool(population->baselineSlots10)) ||
      !SetValue(object, "production_labor", CaptureLaborPool(population->productionSlots14)) ||
      !SetValue(object, "pending_labor_delta", CaptureLaborPool(population->pendingDeltaSlots18)) ||
      !SetValue(object, "predicted_need_by_resource",
                CaptureResourceTable(population->predictedNeedByResource22))) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureCity(int slot) {
  TGreatPower* nation = g_apNationStates[slot];
  TCity* city = nation != 0 ? nation->city : 0;
  if (city == 0) {
    return json_value_init_null();
  }
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0 || json_object_set_number(object, "nation", slot) != JSONSuccess ||
      json_object_set_boolean(object, "power_plant_upgrade_queued",
                              city->powerPlantUpgradeQueuedFlag04 != 0) != JSONSuccess ||
      json_object_set_number(object, "food_substitution_count",
                             static_cast<int>(city->foodSubstitutionCount06)) != JSONSuccess ||
      json_object_set_number(object, "starvation_population_loss",
                             static_cast<int>(city->starvationPopulationLoss08)) != JSONSuccess ||
      json_object_set_number(object, "serialized_state",
                             static_cast<int>(city->serializedState0a)) != JSONSuccess ||
      json_object_set_number(object, "phase_counter", static_cast<int>(city->cityPhaseCounter0c)) !=
          JSONSuccess ||
      !SetValue(object, "metrics_0e", CaptureShortArray(city->cityMetricsBlock0E, 0x1e)) ||
      !SetValue(object, "metrics_4a", CaptureShortArray(city->cityMetricsBlock4A, 9)) ||
      !SetValue(object, "order_count_by_type",
                CaptureShortArray(city->orderCountByType5c, kIndustryActionSlotCount)) ||
      json_object_set_number(object, "rolling_item_production_score",
                             city->rollingItemProductionScore78) != JSONSuccess ||
      json_object_set_boolean(object, "low_production", city->lowProductionFlag7c != 0) !=
          JSONSuccess ||
      json_object_set_boolean(object, "low_stock", city->lowStockFlag7d != 0) != JSONSuccess ||
      !SetValue(object, "reserved_by_type", CaptureResourceTable(city->reservedByType7e)) ||
      json_object_set_number(object, "home_town_tile",
                             city->homeTownMarkerB0 != 0
                                 ? static_cast<int>(city->homeTownMarkerB0->tileIndex)
                                 : -1) != JSONSuccess ||
      json_object_set_number(object, "power_available", static_cast<int>(city->powerAvailableB4)) !=
          JSONSuccess ||
      !SetValue(object, "stock_by_type", CaptureResourceTable(&city->cityStockCottonB6)) ||
      !SetValue(object, "production_orders",
                CaptureShortArray(city->productionOrderTable1dc, 0x10)) ||
      !SetValue(object, "production_accum", CaptureShortArray(city->productionAccum1fc, 0x10)) ||
      !SetValue(object, "production_flags",
                CaptureUnsignedByteArray(city->productionFlags21c, 0x10)) ||
      !SetValue(object, "production_current", CaptureShortArray(city->production22c, 0x10)) ||
      !SetValue(object, "production_progress", CaptureShortArray(city->production24c, 0x10)) ||
      json_object_set_number(object, "population_growth_penalty_ticks",
                             static_cast<int>(city->populationGrowthPenaltyTicks26c)) !=
          JSONSuccess ||
      !SetValue(object, "unmet_resource_retries",
                CaptureResourceTable(city->unmetResourceRetryCount278)) ||
      !SetValue(object, "consumed_production_input_by_type",
                CaptureResourceTable(city->consumedProductionInputByType2a6)) ||
      !SetValue(object, "population", CapturePopulation(city->productionSummary1d8))) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureCities() {
  JSON_Array* cities = 0;
  JSON_Value* value = NewArray(cities);
  if (value == 0) {
    return 0;
  }
  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    if (!AppendValue(cities, CaptureCity(slot))) {
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

int RuntimeShipIndex(const TShip* target) {
  int index = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship == target) {
      return index;
    }
    ++index;
  }
  return -1;
}

int RuntimeTaskForceIndex(const TTaskForce* target) {
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

int RuntimeZoneIndex(const TZone* zone) {
  return zone != 0 ? static_cast<int>(zone->contextOrdinal14) : -1;
}

JSON_Value* CaptureSelectedShips(TMapOrderChildLinkNode* links) {
  JSON_Array* ships = 0;
  JSON_Value* value = NewArray(ships);
  if (value == 0) {
    return 0;
  }
  for (TMapOrderChildLinkNode* link = links; link != 0; link = link->next) {
    const int shipId = RuntimeShipIndex(static_cast<TShip*>(link->payload));
    JSON_Object* ship = 0;
    JSON_Value* shipValue = NewObject(ship);
    if (shipId < 0 || shipValue == 0 ||
        json_object_set_number(ship, "ship", shipId) != JSONSuccess ||
        json_object_set_boolean(ship, "selected", link->active != 0) != JSONSuccess ||
        !AppendValue(ships, shipValue)) {
      if (shipValue != 0 && json_value_get_parent(shipValue) == 0) {
        json_value_free(shipValue);
      }
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureMilitaryUnits() {
  JSON_Array* units = 0;
  JSON_Value* value = NewArray(units);
  if (value == 0) {
    return 0;
  }
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    CIterator cursor(country->militaryUnitList44);
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    int rosterIndex = 0;
    while (cursor.More() != 0) {
      JSON_Object* object = 0;
      JSON_Value* unitValue = NewObject(object);
      if (unit == 0 || unitValue == 0 ||
          json_object_set_number(object, "id", unit->persistentUnitId20) != JSONSuccess ||
          json_object_set_number(object, "nation", nationSlot) != JSONSuccess ||
          json_object_set_number(object, "roster_index", rosterIndex) != JSONSuccess ||
          json_object_set_number(object, "unit_type", static_cast<int>(unit->orderType)) !=
              JSONSuccess ||
          json_object_set_number(object, "stationed_province",
                                 static_cast<int>(unit->tileIndex06)) != JSONSuccess ||
          json_object_set_number(object, "order", static_cast<int>(unit->unitOrder)) !=
              JSONSuccess ||
          json_object_set_number(object, "order_target",
                                 static_cast<int>(unit->orderTargetIndex0C)) != JSONSuccess ||
          json_object_set_number(object, "owner_nation",
                                 static_cast<int>(unit->ownerNationSlot18)) != JSONSuccess ||
          json_object_set_number(object, "roster_id", static_cast<int>(unit->unitRosterId1A)) !=
              JSONSuccess ||
          json_object_set_boolean(object, "registered", unit->militaryRegistrationFlag1C != 0) !=
              JSONSuccess ||
          !SetValue(object, "order_target_tiles", CaptureShortArray(unit->orderTargetTiles28, 3)) ||
          !SetValue(object, "order_target_mirrors",
                    CaptureShortArray(unit->orderTargetTilesMirror2E, 3)) ||
          json_object_set_string(object, "name", static_cast<LPCSTR>(unit->name24)) !=
              JSONSuccess ||
          json_object_set_number(object, "strength", static_cast<int>(unit->strength34)) !=
              JSONSuccess ||
          json_object_set_number(object, "era", static_cast<int>(unit->eraIndex36)) !=
              JSONSuccess ||
          json_object_set_number(object, "experience",
                                 static_cast<int>(unit->experiencePercent38)) != JSONSuccess ||
          json_object_set_number(object, "battle_flags",
                                 static_cast<int>(unit->battleStateFlags3A)) != JSONSuccess ||
          !AppendValue(units, unitValue)) {
        if (unitValue != 0 && json_value_get_parent(unitValue) == 0) {
          json_value_free(unitValue);
        }
        json_value_free(value);
        return 0;
      }
      ++rosterIndex;
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return value;
}

JSON_Value* CaptureCivilianUnits() {
  JSON_Array* units = 0;
  JSON_Value* value = NewArray(units);
  if (value == 0) {
    return 0;
  }
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    const int count =
        nation != 0 && nation->trackedObjectList != 0 ? nation->trackedObjectList->GetCount() : 0;
    for (int ordinal = 1; ordinal <= count; ++ordinal) {
      TCivUnit* unit =
          static_cast<TCivUnit*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      JSON_Object* object = 0;
      JSON_Value* unitValue = NewObject(object);
      if (unit == 0 || unitValue == 0 ||
          json_object_set_number(object, "id", unit->persistentUnitId20) != JSONSuccess ||
          json_object_set_number(object, "nation", nationSlot) != JSONSuccess ||
          json_object_set_number(object, "roster_index", ordinal - 1) != JSONSuccess ||
          json_object_set_number(object, "unit_type", static_cast<int>(unit->orderType)) !=
              JSONSuccess ||
          !SetOptionalNumber(object, "tile", static_cast<int>(unit->tileIndex06)) ||
          json_object_set_number(object, "order", static_cast<int>(unit->unitOrder)) !=
              JSONSuccess ||
          json_object_set_number(object, "order_target",
                                 static_cast<int>(unit->orderTargetIndex0C)) != JSONSuccess ||
          json_object_set_number(object, "owner_nation",
                                 static_cast<int>(unit->ownerNationSlot18)) != JSONSuccess ||
          json_object_set_number(object, "roster_id", static_cast<int>(unit->unitRosterId1A)) !=
              JSONSuccess ||
          json_object_set_boolean(object, "registered", unit->militaryRegistrationFlag1C != 0) !=
              JSONSuccess ||
          json_object_set_number(object, "remaining_turns",
                                 static_cast<int>(unit->remainingTurns24)) != JSONSuccess ||
          !AppendValue(units, unitValue)) {
        if (unitValue != 0 && json_value_get_parent(unitValue) == 0) {
          json_value_free(unitValue);
        }
        json_value_free(value);
        return 0;
      }
    }
  }
  return value;
}

JSON_Value* CaptureShips() {
  JSON_Array* ships = 0;
  JSON_Value* value = NewArray(ships);
  if (value == 0) {
    return 0;
  }
  int shipIndex = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    JSON_Object* object = 0;
    JSON_Value* shipValue = NewObject(object);
    if (shipValue == 0 || json_object_set_number(object, "id", shipIndex) != JSONSuccess ||
        json_object_set_number(object, "ship_type", static_cast<int>(ship->type)) != JSONSuccess ||
        json_object_set_number(object, "location", RuntimeZoneIndex(ship->location)) !=
            JSONSuccess ||
        !SetOptionalNumber(object, "task_force", RuntimeTaskForceIndex(ship->taskForce)) ||
        json_object_set_number(object, "aggression", ship->aggression) != JSONSuccess ||
        json_object_set_number(object, "nation", static_cast<int>(ship->nation)) != JSONSuccess ||
        json_object_set_string(object, "name", static_cast<LPCSTR>(ship->name)) != JSONSuccess ||
        json_object_set_number(object, "strength", static_cast<int>(ship->strength)) !=
            JSONSuccess ||
        json_object_set_number(object, "experience", static_cast<int>(ship->experience)) !=
            JSONSuccess ||
        json_object_set_number(object, "selection", ship->selection) != JSONSuccess ||
        !AppendValue(ships, shipValue)) {
      if (shipValue != 0 && json_value_get_parent(shipValue) == 0) {
        json_value_free(shipValue);
      }
      json_value_free(value);
      return 0;
    }
    ++shipIndex;
  }
  return value;
}

JSON_Value* CaptureTaskForceTarget(const TTaskForce* force) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0) {
    return 0;
  }
  if (force->target == 0) {
    if (json_object_set_string(object, "kind", "none") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (force->shipOrders == 5) {
    if (json_object_set_string(object, "kind", "province") != JSONSuccess ||
        json_object_set_number(
            object, "target",
            static_cast<int>(static_cast<Province*>(force->target)->GetIndex())) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
  } else if (json_object_set_string(object, "kind", "zone") != JSONSuccess ||
             json_object_set_number(
                 object, "target",
                 static_cast<int>(static_cast<TZone*>(force->target)->contextOrdinal14)) !=
                 JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureTaskForces() {
  JSON_Array* taskForces = 0;
  JSON_Value* value = NewArray(taskForces);
  if (value == 0) {
    return 0;
  }
  int forceIndex = 0;
  TTaskForce* force = g_pNavyOrderManager != 0 ? g_pNavyOrderManager->orderQueueHead : 0;
  for (; force != 0; force = force->nextForce) {
    JSON_Object* object = 0;
    JSON_Value* forceValue = NewObject(object);
    if (forceValue == 0 || json_object_set_number(object, "id", forceIndex) != JSONSuccess ||
        json_object_set_number(object, "aggression", force->aggression) != JSONSuccess ||
        json_object_set_number(object, "order", force->shipOrders) != JSONSuccess ||
        !SetValue(object, "target", CaptureTaskForceTarget(force)) ||
        json_object_set_number(object, "location", RuntimeZoneIndex(force->location)) !=
            JSONSuccess ||
        json_object_set_number(object, "nation", static_cast<int>(force->nation)) != JSONSuccess ||
        !SetValue(object, "ship_counts", CaptureShortArray(force->shipCountsByToolbarSlot, 4)) ||
        json_object_set_number(object, "ingot_tile", static_cast<int>(force->ingotTileIndex)) !=
            JSONSuccess ||
        !SetOptionalNumber(object, "flagship", RuntimeShipIndex(force->flagship)) ||
        !SetValue(object, "ships", CaptureSelectedShips(force->shipList)) ||
        !AppendValue(taskForces, forceValue)) {
      if (forceValue != 0 && json_value_get_parent(forceValue) == 0) {
        json_value_free(forceValue);
      }
      json_value_free(value);
      return 0;
    }
    ++forceIndex;
  }
  return value;
}

JSON_Value* CaptureArmyMission(TArmyMission* mission) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* equipage = 0;
  JSON_Value* equipageValue = NewArray(equipage);
  JSON_Array* units = 0;
  JSON_Value* unitsValue = NewArray(units);
  if (value == 0 || equipageValue == 0 || unitsValue == 0 ||
      json_object_set_number(object, "present_location",
                             static_cast<int>(mission->presentLocation14)) != JSONSuccess) {
    json_value_free(unitsValue);
    json_value_free(equipageValue);
    json_value_free(value);
    return 0;
  }
  for (int index = 0; index < 5; ++index) {
    if (json_array_append_number(equipage, FloatBits(mission->requiredEquipageByClass[index])) !=
        JSONSuccess) {
      json_value_free(unitsValue);
      json_value_free(equipageValue);
      json_value_free(value);
      return 0;
    }
  }
  const int unitCount = mission->orderListAt18 != 0 ? mission->orderListAt18->GetCount() : 0;
  for (int ordinal = 1; ordinal <= unitCount; ++ordinal) {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(mission->orderListAt18->GetEntryByOrdinal(ordinal));
    if (unit == 0 || json_array_append_number(units, unit->persistentUnitId20) != JSONSuccess) {
      json_value_free(unitsValue);
      json_value_free(equipageValue);
      json_value_free(value);
      return 0;
    }
  }
  if (!SetValue(object, "required_equipage_bits", equipageValue) ||
      !SetValue(object, "units", unitsValue)) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureNavyMission(TNavyMission* mission) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* equipage = 0;
  JSON_Value* equipageValue = NewArray(equipage);
  if (value == 0 || equipageValue == 0 ||
      json_object_set_number(object, "target_zone", RuntimeZoneIndex(mission->missionTargetZone)) !=
          JSONSuccess ||
      json_object_set_number(object, "resolved_port_zone",
                             RuntimeZoneIndex(mission->resolvedPortZone)) != JSONSuccess ||
      !SetOptionalNumber(object, "selected_ship", RuntimeShipIndex(mission->selectedOrder1c)) ||
      !SetOptionalNumber(object, "task_force", RuntimeTaskForceIndex(mission->taskForce20)) ||
      json_object_set_number(object, "state", mission->navyState28) != JSONSuccess) {
    json_value_free(equipageValue);
    json_value_free(value);
    return 0;
  }
  for (int index = 0; index < 4; ++index) {
    if (json_array_append_number(
            equipage, FloatBits(mission->requiredShipEquipageByCategory[index])) != JSONSuccess) {
      json_value_free(equipageValue);
      json_value_free(value);
      return 0;
    }
  }
  if (!SetValue(object, "required_equipage_bits", equipageValue) ||
      !SetValue(object, "ships", CaptureSelectedShips(mission->orderList24))) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureAttackMission(TAttackProvinceMission* mission) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0 || !SetValue(object, "army", CaptureArmyMission(mission)) ||
      json_object_set_number(object, "target_province",
                             static_cast<int>(mission->targetProvince30)) != JSONSuccess ||
      json_object_set_number(object, "amassing_province",
                             static_cast<int>(mission->amassingProvince32)) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CaptureMissionData(TMission* mission) {
  if (mission->IsKindOf(RUNTIME_CLASS(TInvadeMission))) {
    TInvadeMission* invade = static_cast<TInvadeMission*>(mission);
    JSON_Object* object = 0;
    JSON_Value* value = NewObject(object);
    JSON_Value* beachhead =
        invade->beachhead34 != 0 ? CaptureNavyMission(invade->beachhead34) : json_value_init_null();
    if (value == 0 || beachhead == 0 ||
        json_object_set_string(object, "kind", "invade") != JSONSuccess ||
        !SetValue(object, "attack", CaptureAttackMission(invade)) ||
        !SetValue(object, "beachhead", beachhead)) {
      if (beachhead != 0 && json_value_get_parent(beachhead) == 0) {
        json_value_free(beachhead);
      }
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TAttackProvinceMission))) {
    JSON_Value* value = CaptureAttackMission(static_cast<TAttackProvinceMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "attack_province") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TDefendProvinceMission))) {
    JSON_Value* value = CaptureArmyMission(static_cast<TArmyMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "defend_province") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBlockadePortMission))) {
    TBlockadePortMission* blockade = static_cast<TBlockadePortMission*>(mission);
    JSON_Object* object = 0;
    JSON_Value* value = NewObject(object);
    if (value == 0 || json_object_set_string(object, "kind", "blockade_port") != JSONSuccess ||
        !SetValue(object, "navy", CaptureNavyMission(blockade)) ||
        json_object_set_number(object, "port_zone",
                               RuntimeZoneIndex(blockade->portZoneContext3c)) != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBeachheadMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "beachhead") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TControlSeaZoneMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "control_sea_zone") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TEscortMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "escort") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TScatteredShipsMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
    if (object == 0 || json_object_set_string(object, "kind", "scattered_ships") != JSONSuccess) {
      json_value_free(value);
      return 0;
    }
    return value;
  }
  return 0;
}

JSON_Value* CaptureMissions() {
  JSON_Array* missions = 0;
  JSON_Value* value = NewArray(missions);
  if (value == 0) {
    return 0;
  }
  int missionIndex = 0;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    TSortedList* queue = static_cast<TAutoGreatPower*>(nation)->missionQueue;
    const int missionCount = queue != 0 ? queue->GetCount() : 0;
    for (int queueOrdinal = 1; queueOrdinal <= missionCount; ++queueOrdinal) {
      TMission* mission = static_cast<TMission*>(queue->GetEntryByOrdinal(queueOrdinal));
      if (mission == 0) {
        continue;
      }
      JSON_Object* object = 0;
      JSON_Value* missionValue = NewObject(object);
      if (missionValue == 0 || json_object_set_number(object, "id", missionIndex) != JSONSuccess ||
          json_object_set_number(object, "nation", nationSlot) != JSONSuccess ||
          json_object_set_number(object, "queue_index", queueOrdinal - 1) != JSONSuccess ||
          !SetValue(object, "data", CaptureMissionData(mission)) ||
          json_object_set_number(object, "source_nation", static_cast<int>(mission->nationId04)) !=
              JSONSuccess ||
          json_object_set_number(object, "path_marker", static_cast<int>(mission->pathMarker06)) !=
              JSONSuccess ||
          json_object_set_number(object, "state", static_cast<unsigned int>(mission->state08)) !=
              JSONSuccess ||
          json_object_set_number(object, "importance_bits",
                                 FloatBits(mission->importanceScore0c)) != JSONSuccess ||
          json_object_set_number(object, "marker", static_cast<unsigned int>(mission->marker11)) !=
              JSONSuccess ||
          !AppendValue(missions, missionValue)) {
        if (missionValue != 0 && json_value_get_parent(missionValue) == 0) {
          json_value_free(missionValue);
        }
        json_value_free(value);
        return 0;
      }
      ++missionIndex;
    }
  }
  return value;
}

JSON_Value* CaptureTaggedValues(TSortedByRelationshipList* queue) {
  JSON_Array* values = 0;
  JSON_Value* value = NewArray(values);
  if (value == 0) {
    return 0;
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Object* object = 0;
    JSON_Value* recordValue = NewObject(object);
    if (record == 0 || recordValue == 0 ||
        json_object_set_number(object, "tag", static_cast<int>(record[0])) != JSONSuccess ||
        json_object_set_number(object, "value", static_cast<int>(record[1])) != JSONSuccess ||
        !AppendValue(values, recordValue)) {
      if (recordValue != 0 && json_value_get_parent(recordValue) == 0) {
        json_value_free(recordValue);
      }
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureTurnSummary(TSortedByRelationshipList* queue) {
  JSON_Array* summaries = 0;
  JSON_Value* value = NewArray(summaries);
  if (value == 0) {
    return 0;
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TurnOrderDispatchPacket* packet =
        static_cast<TurnOrderDispatchPacket*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Array* fields = 0;
    JSON_Value* fieldsValue = NewArray(fields);
    if (packet == 0 || fieldsValue == 0 ||
        json_array_append_number(fields, static_cast<int>(packet->turnTick)) != JSONSuccess ||
        json_array_append_number(fields, static_cast<int>(packet->orderKind)) != JSONSuccess ||
        json_array_append_number(fields, static_cast<int>(packet->payload)) != JSONSuccess ||
        json_array_append_number(fields, static_cast<int>(packet->flags)) != JSONSuccess ||
        !AppendValue(summaries, fieldsValue)) {
      if (fieldsValue != 0 && json_value_get_parent(fieldsValue) == 0) {
        json_value_free(fieldsValue);
      }
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureTurnStartEvents(TSortedList* queue) {
  JSON_Array* events = 0;
  JSON_Value* value = NewArray(events);
  if (value == 0) {
    return 0;
  }
  const int count = queue != 0 ? queue->GetCount() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TTurnStartEvent* event = static_cast<TTurnStartEvent*>(queue->GetEntryByOrdinal(ordinal));
    CRuntimeClass* runtimeClass = event != 0 ? event->GetRuntimeClass() : 0;
    JSON_Object* object = 0;
    JSON_Value* eventValue = NewObject(object);
    JSON_Value* landSaleValue = 0;
    if (event != 0 && event->IsKindOf(RUNTIME_CLASS(TLandSaleEvent))) {
      TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
      JSON_Object* landSaleObject = 0;
      landSaleValue = NewObject(landSaleObject);
      if (landSaleValue != 0 &&
          (json_object_set_number(landSaleObject, "province",
                                  static_cast<int>(landSale->tileIndex08)) != JSONSuccess ||
           json_object_set_number(landSaleObject, "nation",
                                  static_cast<int>(landSale->nationCode0a)) != JSONSuccess)) {
        json_value_free(landSaleValue);
        landSaleValue = 0;
      }
    } else {
      landSaleValue = json_value_init_null();
    }
    if (eventValue == 0 || landSaleValue == 0 ||
        json_object_set_string(object, "class",
                               runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown") !=
            JSONSuccess ||
        json_object_set_number(object, "tag", event != 0 ? event->eventTag04 : 0) != JSONSuccess ||
        !SetValue(object, "land_sale", landSaleValue) || !AppendValue(events, eventValue)) {
      if (landSaleValue != 0 && json_value_get_parent(landSaleValue) == 0) {
        json_value_free(landSaleValue);
      }
      if (eventValue != 0 && json_value_get_parent(eventValue) == 0) {
        json_value_free(eventValue);
      }
      json_value_free(value);
      return 0;
    }
  }
  return value;
}

JSON_Value* CaptureNationPendingWork(int nationSlot, TGreatPower* nation) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0 || json_object_set_number(object, "nation", nationSlot) != JSONSuccess ||
      !SetValue(object, "turn_events",
                CaptureTaggedValues(nation != 0 ? nation->turnEventQueue : 0)) ||
      !SetValue(object, "proposals",
                CaptureTaggedValues(nation != 0 ? nation->proposalQueue : 0)) ||
      !SetValue(object, "turn_summary",
                CaptureTurnSummary(nation != 0 ? nation->turnSummaryQueue : 0)) ||
      !SetValue(object, "turn_start_events",
                CaptureTurnStartEvents(nation != 0 ? nation->missionNodeQueue : 0))) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* CapturePending() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* nations = 0;
  JSON_Value* nationsValue = NewArray(nations);
  JSON_Array* transitions = 0;
  JSON_Value* transitionsValue = NewArray(transitions);
  if (value == 0 || nationsValue == 0 || transitionsValue == 0 ||
      json_object_set_number(object, "turn_flow_status_flags",
                             g_pSimMgr != 0 ? g_pSimMgr->turnFlowStatusFlags : 0) != JSONSuccess) {
    json_value_free(transitionsValue);
    json_value_free(nationsValue);
    json_value_free(value);
    return 0;
  }
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (!AppendValue(nations, CaptureNationPendingWork(nationSlot, g_apNationStates[nationSlot]))) {
      json_value_free(transitionsValue);
      json_value_free(nationsValue);
      json_value_free(value);
      return 0;
    }
  }
  TSortedPtrList* queue = g_pDiplomacyTurnStateManager != 0
                              ? g_pDiplomacyTurnStateManager->pendingWarTransitionQueue
                              : 0;
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* pair = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Object* transition = 0;
    JSON_Value* transitionValue = NewObject(transition);
    if (pair == 0 || transitionValue == 0 ||
        json_object_set_number(transition, "first", static_cast<int>(pair[0])) != JSONSuccess ||
        json_object_set_number(transition, "second", static_cast<int>(pair[1])) != JSONSuccess ||
        !AppendValue(transitions, transitionValue)) {
      if (transitionValue != 0 && json_value_get_parent(transitionValue) == 0) {
        json_value_free(transitionValue);
      }
      json_value_free(transitionsValue);
      json_value_free(nationsValue);
      json_value_free(value);
      return 0;
    }
  }
  if (!SetValue(object, "nations", nationsValue) ||
      !SetValue(object, "war_transitions", transitionsValue)) {
    json_value_free(value);
    return 0;
  }
  return value;
}

} // namespace

bool BuildRuntimeGameState(const RuntimeRun& run, JSON_Value** state) {
  if (state == 0 || g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 ||
      g_pSimMgr == 0) {
    return false;
  }
  *state = 0;

  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (value == 0 || !SetValue(object, "turn", CaptureTurn(run)) ||
      json_object_set_number(object, "persistent_unit_id_counter", g_pSimMgr->field_64) !=
          JSONSuccess ||
      !SetValue(object, "world", CaptureWorld()) || !SetValue(object, "rng", CaptureRng()) ||
      !SetValue(object, "nations", CaptureNations()) ||
      !SetValue(object, "cities", CaptureCities()) ||
      !SetValue(object, "military_units", CaptureMilitaryUnits()) ||
      !SetValue(object, "civilian_units", CaptureCivilianUnits()) ||
      !SetValue(object, "ships", CaptureShips()) ||
      !SetValue(object, "task_forces", CaptureTaskForces()) ||
      !SetValue(object, "missions", CaptureMissions()) ||
      !SetValue(object, "pending", CapturePending())) {
    json_value_free(value);
    return false;
  }
  *state = value;
  return true;
}

void CaptureRuntimeGameState(RuntimeRun& run) {
  if (!run.RequestsCapture(kRuntimeCaptureGameState) || run.HasCapture("game_state")) {
    return;
  }
  JSON_Value* state = 0;
  if (!BuildRuntimeGameState(run, &state)) {
    run.RecordAssertion("capture.game_state", "the semantic game-state capture is unavailable",
                        true);
    return;
  }
  run.SetCapture("game_state", state);
}
