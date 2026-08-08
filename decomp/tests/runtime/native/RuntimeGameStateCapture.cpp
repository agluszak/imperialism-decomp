#include "RuntimeGameStateCapture.h"

#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/civilian_domain_types.h"
#include "game/debug/TLaborPool.h"
#include "game/diplomacy_domain_types.h"
#include "game/military_domain_types.h"
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

const char* const kDifficultyNames[5] = {"introductory", "easy", "normal", "hard",
                                         "nigh_on_impossible"};

const char* const kCivilianUnitKindNames[kCivilianUnitKindCount] = {
    "miner",   "prospector", "farmer",    "forester", "engineer",
    "rancher", "fisherman",  "developer", "driller"};

const char* const kMilitaryUnitKindNames[kMilitaryUnitKindCount] = {
    "minutemen",       "skirmishers",      "regulars",
    "grenadiers",      "hussars",          "cuirassiers",
    "light_artillery", "artillery",        "militia",
    "sharpshooters",   "rifle_infantry",   "guards",
    "scouts",          "carbine_cavalry",  "field_artillery",
    "siege_artillery", "conscripts",       "rangers",
    "infantry",        "machine_gunners",  "mechanized_infantry",
    "armor",           "mobile_artillery", "railroad_guns",
    "sappers",         "combat_engineers", "saboteurs",
    "general_era1",    "general_era2",     "general_era3"};

const char* const kIndustryActionSlotNames[kIndustryActionSlotCount] = {
    "slot0", "slot1", "slot2", "slot3",  "slot4",  "slot5",  "slot6",
    "slot7", "slot8", "slot9", "slot10", "slot11", "slot12", "slot13"};

const char* DifficultyName(int value) {
  ASSERT(value >= 0 && value < 5);
  return kDifficultyNames[value];
}

const char* CivilianUnitKindName(int value) {
  ASSERT(value >= 0 && value < kCivilianUnitKindCount);
  return kCivilianUnitKindNames[value];
}

const char* MilitaryUnitKindName(int value) {
  ASSERT(value >= 0 && value < kMilitaryUnitKindCount);
  return kMilitaryUnitKindNames[value];
}

JSON_Value* NewObject(JSON_Object*& object) {
  JSON_Value* value = json_value_init_object();
  object = json_value_get_object(value);
  return value;
}

JSON_Value* NewArray(JSON_Array*& array) {
  JSON_Value* value = json_value_init_array();
  array = json_value_get_array(value);
  return value;
}

void SetOptionalNumber(JSON_Object* object, const char* name, int value) {
  if (value < 0) {
    json_object_set_null(object, name);
  } else {
    json_object_set_number(object, name, value);
  }
}

JSON_Value* CaptureShortArray(const short* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  for (int index = 0; index < count; ++index) {
    json_array_append_number(array, static_cast<int>(values[index]));
  }
  return value;
}

JSON_Value* CaptureIndustryActionCounts(const short* values) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    json_object_set_number(object, kIndustryActionSlotNames[slot], static_cast<int>(values[slot]));
  }
  return value;
}

JSON_Value* CaptureCivilianUnitCounts(const short* values) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  for (int kind = 0; kind < kCivilianUnitKindCount; ++kind) {
    json_object_set_number(object, kCivilianUnitKindNames[kind], static_cast<int>(values[kind]));
  }
  return value;
}

JSON_Value* CaptureMilitaryUnitCounts(const short* values) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  for (int kind = 0; kind < kMilitaryUnitKindCount; ++kind) {
    json_object_set_number(object, kMilitaryUnitKindNames[kind], static_cast<int>(values[kind]));
  }
  return value;
}

JSON_Value* CaptureNationCapacities(const TGreatPower* nation) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_number(object, "available_merchant",
                         static_cast<int>(nation->availableMerchantCapacity));
  json_object_set_number(object, "trade_offer", static_cast<int>(nation->merchantCapacity));
  json_object_set_number(object, "transport", static_cast<int>(nation->transportCapacity));
  json_object_set_number(object, "reserved_transport",
                         static_cast<int>(nation->reservedTransportCapacity));
  return value;
}

JSON_Value* CaptureDiplomacyGrants(const short* values, int count) {
  JSON_Array* grants = 0;
  JSON_Value* value = NewArray(grants);
  for (int index = 0; index < count; ++index) {
    short entry = values[index];
    if (entry == -1) {
      json_array_append_null(grants);
      continue;
    }

    ASSERT(entry >= 0);
    JSON_Object* grant = 0;
    JSON_Value* grantValue = NewObject(grant);
    json_object_set_number(grant, "amount", static_cast<int>(entry & 0x3fff));
    json_object_set_string(grant, "flags", (entry & 0x4000) != 0 ? "RECURRING" : "");
    json_array_append_value(grants, grantValue);
  }
  return value;
}

const char* DiplomacyPolicyName(short policy) {
  switch (policy) {
  case kDiplomacyProposalJoinEmpire:
    return "join_empire";
  case kDiplomacyProposalAlliance:
    return "alliance";
  case kDiplomacyProposalNonAggressionPact:
    return "non_aggression_pact";
  case kDiplomacyProposalPeaceTreaty:
    return "peace_treaty";
  case kDiplomacyProposalDeclareWar:
    return "declare_war";
  case kDiplomacyProposalJoinEmpireWithWarEntanglements:
    return "join_empire_with_war_entanglements";
  case kDiplomacyProposalBuildConsulate:
    return "build_consulate";
  case kDiplomacyProposalBuildEmbassy:
    return "build_embassy";
  default:
    ASSERT(FALSE);
    return "unsupported";
  }
}

JSON_Value* CaptureDiplomacyPolicies(const short* values, int count) {
  JSON_Array* policies = 0;
  JSON_Value* value = NewArray(policies);
  for (int index = 0; index < count; ++index) {
    const short policy = values[index];
    if (policy == -1) {
      json_array_append_null(policies);
    } else {
      json_array_append_string(policies, DiplomacyPolicyName(policy));
    }
  }
  return value;
}

JSON_Value* CaptureIntArray(const int* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  for (int index = 0; index < count; ++index) {
    json_array_append_number(array, values[index]);
  }
  return value;
}

JSON_Value* CaptureUnsignedByteArray(const unsigned char* values, int count) {
  JSON_Array* array = 0;
  JSON_Value* value = NewArray(array);
  for (int index = 0; index < count; ++index) {
    json_array_append_number(array, static_cast<unsigned int>(values[index]));
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
  for (int index = 0; index < kResourceKindCount; ++index) {
    json_object_set_number(table, kResourceNames[index], static_cast<int>(values[index]));
  }
  return value;
}

JSON_Value* CapturePendingActionStatus(const signed char* values) {
  JSON_Object* table = 0;
  JSON_Value* value = NewObject(table);
  for (int index = 0; index < 0x0d; ++index) {
    json_object_set_number(table, kPendingActionNames[index], static_cast<int>(values[index]));
  }
  return value;
}

JSON_Value* CapturePendingActionPayloads(const short* values) {
  JSON_Object* table = 0;
  JSON_Value* value = NewObject(table);
  for (int index = 0; index < 0x0d; ++index) {
    json_object_set_number(table, kPendingActionNames[index], static_cast<int>(values[index]));
  }
  return value;
}

JSON_Value* CaptureLaborPool(const TLaborPool* pool) {
  if (pool == 0) {
    return json_value_init_null();
  }
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_number(object, "low", static_cast<int>(pool->lowSkillCount04));
  json_object_set_number(object, "medium", static_cast<int>(pool->mediumSkillCount06));
  json_object_set_number(object, "high", static_cast<int>(pool->highSkillCount08));
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
  ASSERT(g_pSimMgr != 0);
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_number(object, "scenario_map_index_plus_one", g_pSimMgr->scenarioMapIndexPlusOne);
  json_object_set_number(object, "economic_turn", g_pSimMgr->economicTurn);
  json_object_set_number(object, "phase_code", g_pSimMgr->turnStateCode);
  json_object_set_string(object, "difficulty", DifficultyName(g_pSimMgr->difficultyLevel));
  json_object_set_number(object, "active_nation", g_pSimMgr->activeNationSlot);
  json_object_set_number(object, "selected_nation", run.SelectedNationSlot());
  return value;
}

JSON_Value* CaptureRng() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_number(object, "crt_rand", RuntimeCrtRandState());
  json_object_set_number(object, "map_generation", g_mapGenLcgState_006a38e8);
  json_object_set_number(object, "zone_status", g_zoneStatusCodePrngSeed_006a5aec);
  return value;
}

JSON_Value* CaptureWorld() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* tiles = 0;
  JSON_Value* tilesValue = NewArray(tiles);
  json_object_set_boolean(object, "wraps_horizontally",
                          g_pGlobalMapState->hexNeighborWrapHorizontally == 0);
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    JSON_Object* tileObject = 0;
    JSON_Value* tileValue = NewObject(tileObject);
    JSON_Array* edgeResources = 0;
    JSON_Value* edgeResourcesValue = NewArray(edgeResources);
    json_object_set_number(tileObject, "terrain_kind", static_cast<int>(tile.GetTerrainKind()));
    SetOptionalNumber(tileObject, "owner_nation", static_cast<int>(tile.ownerNationTag04));
    SetOptionalNumber(tileObject, "former_owner_nation",
                      static_cast<int>(tile.formerOwnerNationTag03));
    SetOptionalNumber(tileObject, "province", static_cast<int>(tile.cityRecordIndex));
    json_object_set_number(tileObject, "development_classes",
                           static_cast<int>(tile.developmentClassNibbles0c));
    if (tile.resourceTypeByEdge[0] < 0) {
      json_array_append_null(edgeResources);
    } else {
      json_array_append_number(edgeResources, static_cast<int>(tile.resourceTypeByEdge[0]));
    }
    if (tile.resourceTypeByEdge[1] < 0) {
      json_array_append_null(edgeResources);
    } else {
      json_array_append_number(edgeResources, static_cast<int>(tile.resourceTypeByEdge[1]));
    }
    json_object_set_value(tileObject, "edge_resources", edgeResourcesValue);
    json_object_set_number(tileObject, "rail_flags", static_cast<unsigned int>(tile.railFlags17));
    json_object_set_number(tileObject, "action_state", static_cast<int>(tile.tileActionState16));
    json_object_set_number(tileObject, "active_flags",
                           static_cast<unsigned int>(tile.activeFlags1c));
    json_array_append_value(tiles, tileValue);
  }
  json_object_set_value(object, "tiles", tilesValue);
  return value;
}

JSON_Value* CaptureMajorNation(TGreatPower* nation) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_string(object, "kind", "major");
  json_object_set_boolean(object, "diplomacy_eligible", nation->diplomacyEligibilityA0 != 0);
  json_object_set_value(object, "capacities", CaptureNationCapacities(nation));
  json_object_set_number(object, "grant_total_cost", nation->grantTotalCost);
  json_object_set_number(object, "unfilled_trade_offer_count",
                         static_cast<int>(nation->unfilledTradeOfferCount));
  json_object_set_value(
      object, "diplomacy_policy_by_nation",
      CaptureDiplomacyPolicies(nation->diplomacyPolicyByNation, kNationSlotCount));
  json_object_set_value(object, "diplomacy_grants_by_nation",
                        CaptureDiplomacyGrants(nation->diplomacyGrantByNation, kNationSlotCount));
  json_object_set_value(object, "need_current_by_type",
                        CaptureResourceTable(nation->needCurrentByType));
  json_object_set_value(object, "need_target_by_type",
                        CaptureResourceTable(nation->needTargetByType));
  json_object_set_value(object, "relation_delta_current",
                        CaptureResourceTable(nation->relationDeltaCurrent));
  json_object_set_value(object, "purchased_items_by_resource",
                        CaptureResourceTable(nation->purchasedItemsByResource));
  json_object_set_value(object, "item_potentials", CaptureResourceTable(nation->itemPotentials));
  json_object_set_value(object, "unfilled_trade_turns_by_resource",
                        CaptureResourceTable(nation->unfilledTradeTurnCountsByResource));
  json_object_set_value(object, "transported_items_by_resource",
                        CaptureResourceTable(nation->transportedItemsByResource));
  json_object_set_value(object, "remembered_trade_offers_by_resource",
                        CaptureResourceTable(nation->rememberedTradeOffersByResource));
  json_object_set_value(object, "aid_allocation_matrix",
                        CaptureIntArray(nation->aidAllocationMatrix, 0x170));
  json_object_set_number(object, "budget_pool_base", nation->budgetPoolBase);
  json_object_set_number(object, "budget_pool_delta", nation->budgetPoolDelta);
  json_object_set_number(object, "special_resource_trade_balance", nation->field910);
  json_object_set_value(object, "candidate_nation_flags",
                        CaptureUnsignedByteArray(nation->candidateNationFlags, kNationSlotCount));
  json_object_set_boolean(object, "scenario_initialized", nation->scenarioInitFlag != 0);
  json_object_set_boolean(object, "turn_finished", nation->field904 != 0);
  json_object_set_value(object, "pending_action_status",
                        CapturePendingActionStatus(nation->pendingActionStatus.byAction));
  json_object_set_value(object, "pending_action_payload_by_action",
                        CapturePendingActionPayloads(nation->field8d6));
  json_object_set_number(object, "diplomacy_budget_base", nation->diplomacyBudgetBase);
  json_object_set_number(object, "escalation_counter", static_cast<int>(nation->escalationCounter));
  json_object_set_number(object, "pending_commitment_cost", nation->pendingCommitmentCost);
  json_object_set_number(object, "pressure_counter", static_cast<int>(nation->pressureCounter));
  json_object_set_number(object, "aid_allocation_total", nation->aidAllocationTotal);
  json_object_set_value(object, "colony_boycott_flags",
                        CaptureUnsignedByteArray(nation->colonyBoycottFlags, kNationSlotCount));
  json_object_set_number(object, "military_expenses", nation->militaryExpenses960);
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
  json_object_set_number(common, "owner_nation",
                         static_cast<int>(country->DecodeOwnerNationSlot()));
  json_object_set_number(common, "treasury", country->treasuryValue10);
  SetOptionalNumber(common, "home_tile", country->homeTileIndex);
  json_object_set_value(common, "trade_policy_by_nation",
                        CaptureShortArray(country->needLevelByNation, kNationSlotCount));
  json_object_set_value(object, "common", commonValue);

  if (slot < kMajorNationCount) {
    TGreatPower* nation = g_apNationStates[slot];
    json_object_set_value(object, "data", CaptureMajorNation(nation));
  } else {
    JSON_Object* data = 0;
    JSON_Value* dataValue = NewObject(data);
    json_object_set_string(data, "kind", "minor");
    json_object_set_value(object, "data", dataValue);
  }
  return value;
}

JSON_Value* CaptureNations() {
  JSON_Array* nations = 0;
  JSON_Value* value = NewArray(nations);
  for (int slot = 0; slot < kNationSlotCount; ++slot) {
    json_array_append_value(nations, CaptureNation(slot));
  }
  return value;
}

JSON_Value* CapturePopulation(const TPopulationMgr* population) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_number(object, "count", static_cast<int>(population->populationCount08));
  json_object_set_number(object, "count_float_bits", FloatBits(population->populationCountFloat0c));
  json_object_set_number(object, "strength", static_cast<int>(population->strength));
  json_object_set_number(object, "extra", static_cast<int>(population->extraAt1e));
  json_object_set_number(object, "phase_value", static_cast<int>(population->fieldAt20));
  json_object_set_value(object, "baseline_labor", CaptureLaborPool(population->baselineSlots10));
  json_object_set_value(object, "production_labor",
                        CaptureLaborPool(population->productionSlots14));
  json_object_set_value(object, "pending_labor_delta",
                        CaptureLaborPool(population->pendingDeltaSlots18));
  json_object_set_value(object, "predicted_need_by_resource",
                        CaptureResourceTable(population->predictedNeedByResource22));
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
  json_object_set_boolean(object, "power_plant_upgrade_queued",
                          city->powerPlantUpgradeQueuedFlag04 != 0);
  json_object_set_number(object, "food_substitution_count",
                         static_cast<int>(city->foodSubstitutionCount06));
  json_object_set_number(object, "starvation_population_loss",
                         static_cast<int>(city->starvationPopulationLoss08));
  json_object_set_number(object, "serialized_state", static_cast<int>(city->serializedState0a));
  json_object_set_number(object, "phase_counter", static_cast<int>(city->cityPhaseCounter0c));
  json_object_set_value(object, "military_recruit_count_by_kind",
                        CaptureMilitaryUnitCounts(city->militaryRecruitCountByKind));
  json_object_set_value(object, "civilian_recruit_count_by_kind",
                        CaptureCivilianUnitCounts(city->civilianRecruitCountByKind));
  json_object_set_value(object, "order_count_by_type",
                        CaptureIndustryActionCounts(city->orderCountByType5c));
  json_object_set_number(object, "rolling_item_production_score",
                         city->rollingItemProductionScore78);
  json_object_set_boolean(object, "low_production", city->lowProductionFlag7c != 0);
  json_object_set_boolean(object, "low_stock", city->lowStockFlag7d != 0);
  json_object_set_value(object, "reserved_by_type", CaptureResourceTable(city->reservedByType7e));
  if (city->homeTownMarkerB0 == 0) {
    json_object_set_null(object, "home_town_tile");
  } else {
    json_object_set_number(object, "home_town_tile",
                           static_cast<int>(city->homeTownMarkerB0->tileIndex));
  }
  json_object_set_number(object, "power_available", static_cast<int>(city->powerAvailableB4));
  json_object_set_value(object, "stock_by_type", CaptureResourceTable(&city->cityStockCottonB6));
  json_object_set_value(object, "production_orders",
                        CaptureShortArray(city->productionOrderTable1dc, 0x10));
  json_object_set_value(object, "production_accum",
                        CaptureShortArray(city->productionAccum1fc, 0x10));
  json_object_set_value(object, "production_flags",
                        CaptureUnsignedByteArray(city->productionFlags21c, 0x10));
  json_object_set_value(object, "production_current", CaptureShortArray(city->production22c, 0x10));
  json_object_set_value(object, "production_progress",
                        CaptureShortArray(city->production24c, 0x10));
  json_object_set_number(object, "population_growth_penalty_ticks",
                         static_cast<int>(city->populationGrowthPenaltyTicks26c));
  json_object_set_value(object, "unmet_resource_retries",
                        CaptureResourceTable(city->unmetResourceRetryCount278));
  json_object_set_value(object, "consumed_production_input_by_type",
                        CaptureResourceTable(city->consumedProductionInputByType2a6));
  json_object_set_value(object, "population", CapturePopulation(city->productionSummary1d8));
  return value;
}

JSON_Value* CaptureCities() {
  JSON_Array* cities = 0;
  JSON_Value* value = NewArray(cities);
  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    json_array_append_value(cities, CaptureCity(slot));
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
  for (TMapOrderChildLinkNode* link = links; link != 0; link = link->next) {
    JSON_Object* ship = 0;
    JSON_Value* shipValue = NewObject(ship);
    json_object_set_number(ship, "ship", RuntimeShipIndex(static_cast<TShip*>(link->payload)));
    json_object_set_boolean(ship, "selected", link->active != 0);
    json_array_append_value(ships, shipValue);
  }
  return value;
}

JSON_Value* CaptureMilitaryUnits() {
  JSON_Array* units = 0;
  JSON_Value* value = NewArray(units);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    CIterator cursor(country->militaryUnitList44);
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      JSON_Object* object = 0;
      JSON_Value* unitValue = NewObject(object);
      json_object_set_number(object, "id", unit->persistentUnitId20);
      json_object_set_number(object, "nation", nationSlot);
      json_object_set_string(object, "unit_type",
                             MilitaryUnitKindName(static_cast<int>(unit->orderType)));
      json_object_set_number(object, "stationed_province", static_cast<int>(unit->tileIndex06));
      json_object_set_number(object, "order", static_cast<int>(unit->unitOrder));
      json_object_set_number(object, "order_target", static_cast<int>(unit->orderTargetIndex0C));
      json_object_set_number(object, "owner_nation", static_cast<int>(unit->ownerNationSlot18));
      json_object_set_number(object, "roster_id", static_cast<int>(unit->unitRosterId1A));
      json_object_set_boolean(object, "registered", unit->militaryRegistrationFlag1C != 0);
      json_object_set_value(object, "order_target_tiles",
                            CaptureShortArray(unit->orderTargetTiles28, 3));
      json_object_set_value(object, "order_target_mirrors",
                            CaptureShortArray(unit->orderTargetTilesMirror2E, 3));
      json_object_set_string(object, "name", static_cast<LPCSTR>(unit->name24));
      json_object_set_number(object, "strength", static_cast<int>(unit->strength34));
      json_object_set_number(object, "era", static_cast<int>(unit->eraIndex36));
      json_object_set_number(object, "experience", static_cast<int>(unit->experiencePercent38));
      json_object_set_number(object, "battle_flags", static_cast<int>(unit->battleStateFlags3A));
      json_array_append_value(units, unitValue);
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return value;
}

JSON_Value* CaptureCivilianUnits() {
  JSON_Array* units = 0;
  JSON_Value* value = NewArray(units);
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    const int count =
        nation != 0 && nation->trackedObjectList != 0 ? nation->trackedObjectList->GetCount() : 0;
    for (int ordinal = 1; ordinal <= count; ++ordinal) {
      TCivUnit* unit =
          static_cast<TCivUnit*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      JSON_Object* object = 0;
      JSON_Value* unitValue = NewObject(object);
      json_object_set_number(object, "id", unit->persistentUnitId20);
      json_object_set_number(object, "nation", nationSlot);
      json_object_set_string(object, "unit_type",
                             CivilianUnitKindName(static_cast<int>(unit->orderType)));
      SetOptionalNumber(object, "tile", static_cast<int>(unit->tileIndex06));
      json_object_set_number(object, "order", static_cast<int>(unit->unitOrder));
      json_object_set_number(object, "order_target", static_cast<int>(unit->orderTargetIndex0C));
      json_object_set_number(object, "owner_nation", static_cast<int>(unit->ownerNationSlot18));
      json_object_set_number(object, "roster_id", static_cast<int>(unit->unitRosterId1A));
      json_object_set_boolean(object, "registered", unit->militaryRegistrationFlag1C != 0);
      json_object_set_number(object, "remaining_turns", static_cast<int>(unit->remainingTurns24));
      json_array_append_value(units, unitValue);
    }
  }
  return value;
}

JSON_Value* CaptureShips() {
  JSON_Array* ships = 0;
  JSON_Value* value = NewArray(ships);
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    JSON_Object* object = 0;
    JSON_Value* shipValue = NewObject(object);
    json_object_set_number(object, "ship_type", static_cast<int>(ship->type));
    json_object_set_number(object, "location", RuntimeZoneIndex(ship->location));
    SetOptionalNumber(object, "task_force", RuntimeTaskForceIndex(ship->taskForce));
    json_object_set_number(object, "aggression", ship->aggression);
    json_object_set_number(object, "nation", static_cast<int>(ship->nation));
    json_object_set_string(object, "name", static_cast<LPCSTR>(ship->name));
    json_object_set_number(object, "strength", static_cast<int>(ship->strength));
    json_object_set_number(object, "experience", static_cast<int>(ship->experience));
    json_object_set_number(object, "selection", ship->selection);
    json_array_append_value(ships, shipValue);
  }
  return value;
}

JSON_Value* CaptureTaskForceTarget(const TTaskForce* force) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  if (force->target == 0) {
    json_object_set_string(object, "kind", "none");
    return value;
  }
  if (force->shipOrders == 5) {
    json_object_set_string(object, "kind", "province");
    json_object_set_number(object, "target",
                           static_cast<int>(static_cast<Province*>(force->target)->GetIndex()));
  } else {
    json_object_set_string(object, "kind", "zone");
    json_object_set_number(object, "target",
                           static_cast<int>(static_cast<TZone*>(force->target)->contextOrdinal14));
  }
  return value;
}

JSON_Value* CaptureTaskForces() {
  JSON_Array* taskForces = 0;
  JSON_Value* value = NewArray(taskForces);
  TTaskForce* force = g_pNavyOrderManager != 0 ? g_pNavyOrderManager->orderQueueHead : 0;
  for (; force != 0; force = force->nextForce) {
    JSON_Object* object = 0;
    JSON_Value* forceValue = NewObject(object);
    json_object_set_number(object, "aggression", force->aggression);
    json_object_set_number(object, "order", force->shipOrders);
    json_object_set_value(object, "target", CaptureTaskForceTarget(force));
    json_object_set_number(object, "location", RuntimeZoneIndex(force->location));
    json_object_set_number(object, "nation", static_cast<int>(force->nation));
    json_object_set_value(object, "ship_counts",
                          CaptureShortArray(force->shipCountsByToolbarSlot, 4));
    json_object_set_number(object, "ingot_tile", static_cast<int>(force->ingotTileIndex));
    SetOptionalNumber(object, "flagship", RuntimeShipIndex(force->flagship));
    json_object_set_value(object, "ships", CaptureSelectedShips(force->shipList));
    json_array_append_value(taskForces, forceValue);
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
  json_object_set_number(object, "present_location", static_cast<int>(mission->presentLocation14));
  for (int index = 0; index < 5; ++index) {
    json_array_append_number(equipage, FloatBits(mission->requiredEquipageByClass[index]));
  }
  const int unitCount = mission->orderListAt18 != 0 ? mission->orderListAt18->GetCount() : 0;
  for (int ordinal = 1; ordinal <= unitCount; ++ordinal) {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(mission->orderListAt18->GetEntryByOrdinal(ordinal));
    json_array_append_number(units, unit->persistentUnitId20);
  }
  json_object_set_value(object, "required_equipage_bits", equipageValue);
  json_object_set_value(object, "units", unitsValue);
  return value;
}

JSON_Value* CaptureNavyMission(TNavyMission* mission) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* equipage = 0;
  JSON_Value* equipageValue = NewArray(equipage);
  json_object_set_number(object, "target_zone", RuntimeZoneIndex(mission->missionTargetZone));
  json_object_set_number(object, "resolved_port_zone", RuntimeZoneIndex(mission->resolvedPortZone));
  SetOptionalNumber(object, "selected_ship", RuntimeShipIndex(mission->selectedOrder1c));
  SetOptionalNumber(object, "task_force", RuntimeTaskForceIndex(mission->taskForce20));
  json_object_set_number(object, "state", mission->navyState28);
  for (int index = 0; index < 4; ++index) {
    json_array_append_number(equipage, FloatBits(mission->requiredShipEquipageByCategory[index]));
  }
  json_object_set_value(object, "required_equipage_bits", equipageValue);
  json_object_set_value(object, "ships", CaptureSelectedShips(mission->orderList24));
  return value;
}

JSON_Value* CaptureAttackMission(TAttackProvinceMission* mission) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_value(object, "army", CaptureArmyMission(mission));
  json_object_set_number(object, "target_province", static_cast<int>(mission->targetProvince30));
  json_object_set_number(object, "amassing_province",
                         static_cast<int>(mission->amassingProvince32));
  return value;
}

JSON_Value* CaptureMissionData(TMission* mission) {
  if (mission->IsKindOf(RUNTIME_CLASS(TInvadeMission))) {
    TInvadeMission* invade = static_cast<TInvadeMission*>(mission);
    JSON_Object* object = 0;
    JSON_Value* value = NewObject(object);
    json_object_set_string(object, "kind", "invade");
    json_object_set_value(object, "attack", CaptureAttackMission(invade));
    json_object_set_value(object, "beachhead",
                          invade->beachhead34 != 0 ? CaptureNavyMission(invade->beachhead34)
                                                   : json_value_init_null());
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TAttackProvinceMission))) {
    JSON_Value* value = CaptureAttackMission(static_cast<TAttackProvinceMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "attack_province");
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TDefendProvinceMission))) {
    JSON_Value* value = CaptureArmyMission(static_cast<TArmyMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "defend_province");
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBlockadePortMission))) {
    TBlockadePortMission* blockade = static_cast<TBlockadePortMission*>(mission);
    JSON_Object* object = 0;
    JSON_Value* value = NewObject(object);
    json_object_set_string(object, "kind", "blockade_port");
    json_object_set_value(object, "navy", CaptureNavyMission(blockade));
    json_object_set_number(object, "port_zone", RuntimeZoneIndex(blockade->portZoneContext3c));
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBeachheadMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "beachhead");
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TControlSeaZoneMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "control_sea_zone");
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TEscortMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "escort");
    return value;
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TScatteredShipsMission))) {
    JSON_Value* value = CaptureNavyMission(static_cast<TNavyMission*>(mission));
    json_object_set_string(json_value_get_object(value), "kind", "scattered_ships");
    return value;
  }
  return json_value_init_null();
}

JSON_Value* CaptureMissions() {
  JSON_Array* missions = 0;
  JSON_Value* value = NewArray(missions);
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
      json_object_set_number(object, "nation", nationSlot);
      json_object_set_number(object, "queue_index", queueOrdinal - 1);
      json_object_set_value(object, "data", CaptureMissionData(mission));
      json_object_set_number(object, "source_nation", static_cast<int>(mission->nationId04));
      json_object_set_number(object, "path_marker", static_cast<int>(mission->pathMarker06));
      json_object_set_number(object, "state", static_cast<unsigned int>(mission->state08));
      json_object_set_number(object, "importance_bits", FloatBits(mission->importanceScore0c));
      json_object_set_number(object, "marker", static_cast<unsigned int>(mission->marker11));
      json_array_append_value(missions, missionValue);
    }
  }
  return value;
}

JSON_Value* CaptureTaggedValues(TSortedByRelationshipList* queue) {
  JSON_Array* values = 0;
  JSON_Value* value = NewArray(values);
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Object* object = 0;
    JSON_Value* recordValue = NewObject(object);
    json_object_set_number(object, "tag", static_cast<int>(record[0]));
    json_object_set_number(object, "value", static_cast<int>(record[1]));
    json_array_append_value(values, recordValue);
  }
  return value;
}

JSON_Value* CaptureTurnSummary(TSortedByRelationshipList* queue) {
  JSON_Array* summaries = 0;
  JSON_Value* value = NewArray(summaries);
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TurnOrderDispatchPacket* packet =
        static_cast<TurnOrderDispatchPacket*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Object* object = 0;
    JSON_Value* summaryValue = NewObject(object);
    json_object_set_number(object, "turn_tick", static_cast<int>(packet->turnTick));
    json_object_set_number(object, "order_kind", static_cast<int>(packet->orderKind));
    json_object_set_number(object, "payload", static_cast<int>(packet->payload));
    json_object_set_number(object, "flags", static_cast<int>(packet->flags));
    json_array_append_value(summaries, summaryValue);
  }
  return value;
}

JSON_Value* CaptureTurnStartEvents(TSortedList* queue) {
  JSON_Array* events = 0;
  JSON_Value* value = NewArray(events);
  const int count = queue != 0 ? queue->GetCount() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TTurnStartEvent* event = static_cast<TTurnStartEvent*>(queue->GetEntryByOrdinal(ordinal));
    CRuntimeClass* runtimeClass = event != 0 ? event->GetRuntimeClass() : 0;
    JSON_Object* object = 0;
    JSON_Value* eventValue = NewObject(object);
    json_object_set_string(object, "class",
                           runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown");
    json_object_set_number(object, "tag", event != 0 ? event->eventTag04 : 0);
    if (event != 0 && event->IsKindOf(RUNTIME_CLASS(TLandSaleEvent))) {
      TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
      JSON_Object* landSaleObject = 0;
      JSON_Value* landSaleValue = NewObject(landSaleObject);
      json_object_set_number(landSaleObject, "province", static_cast<int>(landSale->tileIndex08));
      json_object_set_number(landSaleObject, "nation", static_cast<int>(landSale->nationCode0a));
      json_object_set_value(object, "land_sale", landSaleValue);
    } else {
      json_object_set_value(object, "land_sale", json_value_init_null());
    }
    json_array_append_value(events, eventValue);
  }
  return value;
}

JSON_Value* CaptureNationPendingWork(TGreatPower* nation) {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_value(object, "turn_events",
                        CaptureTaggedValues(nation != 0 ? nation->turnEventQueue : 0));
  json_object_set_value(object, "proposals",
                        CaptureTaggedValues(nation != 0 ? nation->proposalQueue : 0));
  json_object_set_value(object, "turn_summary",
                        CaptureTurnSummary(nation != 0 ? nation->turnSummaryQueue : 0));
  json_object_set_value(object, "turn_start_events",
                        CaptureTurnStartEvents(nation != 0 ? nation->missionNodeQueue : 0));
  return value;
}

JSON_Value* CapturePending() {
  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  JSON_Array* nations = 0;
  JSON_Value* nationsValue = NewArray(nations);
  JSON_Array* transitions = 0;
  JSON_Value* transitionsValue = NewArray(transitions);
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    json_array_append_value(nations, CaptureNationPendingWork(g_apNationStates[nationSlot]));
  }
  TSortedPtrList* queue = g_pDiplomacyTurnStateManager != 0
                              ? g_pDiplomacyTurnStateManager->pendingWarTransitionQueue
                              : 0;
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* pair = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JSON_Object* transition = 0;
    JSON_Value* transitionValue = NewObject(transition);
    json_object_set_number(transition, "first", static_cast<int>(pair[0]));
    json_object_set_number(transition, "second", static_cast<int>(pair[1]));
    json_array_append_value(transitions, transitionValue);
  }
  json_object_set_value(object, "nations", nationsValue);
  json_object_set_value(object, "war_transitions", transitionsValue);
  return value;
}

} // namespace

bool BuildRuntimeGameState(const RuntimeRun& run, JSON_Value** state) {
  if (state == 0 || g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 ||
      g_pSimMgr == 0) {
    return false;
  }

  JSON_Object* object = 0;
  JSON_Value* value = NewObject(object);
  json_object_set_value(object, "turn", CaptureTurn(run));
  json_object_set_number(object, "persistent_unit_id_counter", g_pSimMgr->field_64);
  json_object_set_value(object, "world", CaptureWorld());
  json_object_set_value(object, "rng", CaptureRng());
  json_object_set_value(object, "nations", CaptureNations());
  json_object_set_value(object, "cities", CaptureCities());
  json_object_set_value(object, "military_units", CaptureMilitaryUnits());
  json_object_set_value(object, "civilian_units", CaptureCivilianUnits());
  json_object_set_value(object, "ships", CaptureShips());
  json_object_set_value(object, "task_forces", CaptureTaskForces());
  json_object_set_value(object, "missions", CaptureMissions());
  json_object_set_value(object, "pending", CapturePending());
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
