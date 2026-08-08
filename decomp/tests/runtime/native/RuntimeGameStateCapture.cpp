#include "RuntimeGameStateCapture.h"

#include "JsonArray.h"
#include "JsonObject.h"
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
#include "game/globals/trade_ui_globals.h"
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
#include "game/ui_widgets/TTradeMgr.h"

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

const char* const kResourceNames[kResourceKindCount] = {
    "cotton", "wool",   "timber", "coal",  "iron",      "horses",   "oil",       "food",
    "fabric", "lumber", "paper",  "steel", "fuel",      "clothing", "furniture", "hardware",
    "arms",   "grain",  "fruit",  "fish",  "livestock", "gems",     "gold"};

const char* DifficultyName(int value) {
  ASSERT(value >= 0 && value < 5);
  return kDifficultyNames[value];
}

const char* CivilianUnitKindName(int value) {
  ASSERT(value >= 0 && value < kCivilianUnitKindCount);
  return kCivilianUnitKindNames[value];
}

const char* CivilianWorkOrderName(UnitOrder order) {
  switch (order) {
  case kUnitOrderIdle:
    return "idle";
  case kUnitOrderRedeploy:
    return "redeploy";
  case kUnitOrderSleep:
    return "sleep";
  case kUnitOrderLayRail:
    return "lay_rail";
  case kUnitOrderBuildDepot:
    return "build_depot";
  case kUnitOrderBuildPort:
    return "build_port";
  case kUnitOrderProspect:
    return "prospect";
  case kUnitOrderDevelopResource:
    return "develop_resource";
  case kUnitOrderBuildFort:
    return "build_fort";
  case kUnitOrderPurchaseLand:
    return "purchase_land";
  default:
    ASSERT(0);
    return "";
  }
}

JSON_Value* CaptureTileDevelopment(const TTerrainStateRecord& tile) {
  const unsigned char packed = static_cast<unsigned char>(tile.developmentClassNibbles0c);
  JsonObject object;
  JsonArray visibleToMajors;
  object.Set("surface", static_cast<unsigned int>(packed & 0x0f));
  object.Set("extractive", static_cast<unsigned int>(packed >> 4));
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    visibleToMajors.Add((tile.pendingDevelopmentFlag0d & (1 << nationSlot)) != 0);
  }
  object.Set("resource_visible_to_majors", visibleToMajors.Release());
  return object.Release();
}

const char* const kStrategicHexDirectionNames[kStrategicHexDirectionCount] = {
    "NORTH_EAST", "EAST", "SOUTH_EAST", "SOUTH_WEST", "WEST", "NORTH_WEST"};

void SetDirectionalLinks(JsonObject& object, const char* name, unsigned char flags) {
  char text[64];
  text[0] = '\0';
  ASSERT((flags & ~0x3f) == 0);

  for (int direction = 0; direction < kStrategicHexDirectionCount; ++direction) {
    if ((flags & (1 << direction)) == 0) {
      continue;
    }
    if (text[0] != '\0') {
      strcat(text, " | ");
    }
    strcat(text, kStrategicHexDirectionNames[direction]);
  }
  object.Set(name, text);
}

const char* MilitaryUnitKindName(int value) {
  ASSERT(value >= 0 && value < kMilitaryUnitKindCount);
  return kMilitaryUnitKindNames[value];
}

const char* IndustryActionSlotName(int value) {
  ASSERT(value >= 0 && value < kIndustryActionSlotCount);
  return kIndustryActionSlotNames[value];
}

JSON_Value* CaptureShortArray(const short* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    array.Add(static_cast<int>(values[index]));
  }
  return array.Release();
}

JSON_Value* CaptureIndustryActionCounts(const short* values) {
  JsonObject object;
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    object.Set(kIndustryActionSlotNames[slot], static_cast<int>(values[slot]));
  }
  return object.Release();
}

JSON_Value* CaptureCivilianUnitCounts(const short* values) {
  JsonObject object;
  for (int kind = 0; kind < kCivilianUnitKindCount; ++kind) {
    object.Set(kCivilianUnitKindNames[kind], static_cast<int>(values[kind]));
  }
  return object.Release();
}

JSON_Value* CaptureMilitaryUnitCounts(const short* values) {
  JsonObject object;
  for (int kind = 0; kind < kMilitaryUnitKindCount; ++kind) {
    object.Set(kMilitaryUnitKindNames[kind], static_cast<int>(values[kind]));
  }
  return object.Release();
}

JSON_Value* CaptureNationCapacities(const TGreatPower* nation) {
  JsonObject object;
  object.Set("available_merchant", static_cast<int>(nation->availableMerchantCapacity));
  object.Set("merchant_capacity", static_cast<int>(nation->merchantCapacity));
  object.Set("transport", static_cast<int>(nation->transportCapacity));
  object.Set("reserved_transport", static_cast<int>(nation->reservedTransportCapacity));
  return object.Release();
}

JSON_Value* CaptureDiplomacyGrants(const short* values, int count) {
  JsonArray grants;
  for (int index = 0; index < count; ++index) {
    short entry = values[index];
    if (entry == -1) {
      grants.AddNull();
      continue;
    }

    ASSERT(entry >= 0);
    JsonObject grant;
    grant.Set("amount", static_cast<int>(entry & 0x3fff));
    grant.Set("flags", (entry & 0x4000) != 0 ? "RECURRING" : "");
    grants.Add(grant.Release());
  }
  return grants.Release();
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
  JsonArray policies;
  for (int index = 0; index < count; ++index) {
    const short policy = values[index];
    if (policy == -1) {
      policies.AddNull();
    } else {
      policies.Add(DiplomacyPolicyName(policy));
    }
  }
  return policies.Release();
}

JSON_Value* CaptureUnsignedByteArray(const unsigned char* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    array.Add(static_cast<unsigned int>(values[index]));
  }
  return array.Release();
}

unsigned int FloatBits(float value) {
  unsigned int bits = 0;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
}

JSON_Value* CaptureResourceTable(const short* values) {
  JsonObject table;
  for (int index = 0; index < kResourceKindCount; ++index) {
    table.Set(kResourceNames[index], static_cast<int>(values[index]));
  }
  return table.Release();
}

JSON_Value* CaptureResourceTable(const int* values) {
  JsonObject table;
  for (int index = 0; index < kResourceKindCount; ++index) {
    table.Set(kResourceNames[index], values[index]);
  }
  return table.Release();
}

JSON_Value* CaptureMarket() {
  JsonObject market;
  JsonObject rows;
  for (int resource = kResourceCotton; resource < kResourceManufacturedEnd; ++resource) {
    const TTradeMgr::NationMetricCategoryRow& row = g_pTradeMgr->categoryRows[resource];
    JsonObject rowObject;
    rowObject.Set("previous_price", static_cast<int>(row.previousPrice));
    rowObject.Set("price", static_cast<int>(row.price));
    rowObject.Set("base_price", static_cast<int>(row.basePrice));
    rowObject.Set("request_count", static_cast<int>(row.numRequests));
    rowObject.Set("offer_count", static_cast<int>(row.numOffers));
    rowObject.Set("amount_offered", static_cast<int>(row.amountOffered));
    rowObject.Set("adjusted_offer_count", row.adjustedNumOffers);
    rows.Set(kResourceNames[resource], rowObject.Release());
  }
  market.Set("rows", rows.Release());
  return market.Release();
}

JSON_Value* CaptureAidAllocationByMinorNation(const int* values) {
  JsonArray rows;
  for (int minorNationSlot = kMinorNationFirstSlot; minorNationSlot < kNationSlotCount;
       ++minorNationSlot) {
    const int row = minorNationSlot - kMinorNationFirstSlot;
    rows.Add(CaptureResourceTable(values + row * kResourceKindCount));
  }
  return rows.Release();
}

JSON_Value* CapturePendingActionStatus(const signed char* values) {
  JsonObject table;
  for (int index = 0; index < 0x0d; ++index) {
    table.Set(kPendingActionNames[index], static_cast<int>(values[index]));
  }
  return table.Release();
}

JSON_Value* CapturePendingActionPayloads(const short* values) {
  JsonObject table;
  for (int index = 0; index < 0x0d; ++index) {
    table.Set(kPendingActionNames[index], static_cast<int>(values[index]));
  }
  return table.Release();
}

JSON_Value* CaptureLaborPool(const TLaborPool* pool) {
  if (pool == 0) {
    return JsonNullValue();
  }
  JsonObject object;
  object.Set("low", static_cast<int>(pool->lowSkillCount04));
  object.Set("medium", static_cast<int>(pool->mediumSkillCount06));
  object.Set("high", static_cast<int>(pool->highSkillCount08));
  return object.Release();
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
  JsonObject object;
  object.Set("scenario_map_index_plus_one", g_pSimMgr->scenarioMapIndexPlusOne);
  object.Set("economic_turn", g_pSimMgr->economicTurn);
  object.Set("phase_code", g_pSimMgr->turnStateCode);
  object.Set("difficulty", DifficultyName(g_pSimMgr->difficultyLevel));
  object.Set("active_nation", g_pSimMgr->activeNationSlot);
  object.Set("selected_nation", run.SelectedNationSlot());
  return object.Release();
}

JSON_Value* CaptureRng() {
  JsonObject object;
  object.Set("crt_rand", RuntimeCrtRandState());
  object.Set("map_generation", g_mapGenLcgState_006a38e8);
  object.Set("zone_status", g_zoneStatusCodePrngSeed_006a5aec);
  return object.Release();
}

JSON_Value* CaptureWorld() {
  JsonObject object;
  JsonArray tiles;
  object.Set("wraps_horizontally",
             g_pGlobalMapState->hexNeighborWrapHorizontally == 0 ? true : false);
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    JsonObject tileObject;
    JsonArray edgeResources;
    tileObject.Set("terrain_kind", static_cast<int>(tile.GetTerrainKind()));
    tileObject.SetOptional("owner_nation", static_cast<int>(tile.ownerNationTag04));
    tileObject.SetOptional("former_owner_nation", static_cast<int>(tile.formerOwnerNationTag03));
    tileObject.SetOptional("province", static_cast<int>(tile.cityRecordIndex));
    tileObject.Set("development", CaptureTileDevelopment(tile));
    if (tile.resourceTypeByEdge[0] < 0) {
      edgeResources.AddNull();
    } else {
      edgeResources.Add(static_cast<int>(tile.resourceTypeByEdge[0]));
    }
    if (tile.resourceTypeByEdge[1] < 0) {
      edgeResources.AddNull();
    } else {
      edgeResources.Add(static_cast<int>(tile.resourceTypeByEdge[1]));
    }
    tileObject.Set("edge_resources", edgeResources.Release());
    SetDirectionalLinks(tileObject, "transport_links",
                        static_cast<unsigned char>(tile.adjacencyBits06));
    SetDirectionalLinks(tileObject, "pending_rail_links", tile.railFlags17);
    tileObject.Set("action_state", static_cast<int>(tile.tileActionState16));
    tileObject.Set("active_flags", static_cast<unsigned int>(tile.activeFlags1c));
    tileObject.Set("region_marker", static_cast<int>(tile.regionSubtypeTag05));
    tileObject.Set("river_sprite_code", static_cast<unsigned int>(tile.riverSpriteCode));
    tiles.Add(tileObject.Release());
  }
  object.Set("tiles", tiles.Release());
  return object.Release();
}

JSON_Value* CaptureMajorNation(TGreatPower* nation) {
  JsonObject object;
  object.Set("kind", "major");
  object.Set("diplomacy_eligible", nation->diplomacyEligibilityA0 != 0 ? true : false);
  object.Set("capacities", CaptureNationCapacities(nation));
  object.Set("grant_total_cost", nation->grantTotalCost);
  object.Set("unfilled_trade_offer_count", static_cast<int>(nation->unfilledTradeOfferCount));
  object.Set("diplomacy_policy_by_nation",
             CaptureDiplomacyPolicies(nation->diplomacyPolicyByNation, kNationSlotCount));
  object.Set("diplomacy_grants_by_nation",
             CaptureDiplomacyGrants(nation->diplomacyGrantByNation, kNationSlotCount));
  object.Set("need_current_by_type", CaptureResourceTable(nation->needCurrentByType));
  object.Set("need_target_by_type", CaptureResourceTable(nation->needTargetByType));
  object.Set("relation_delta_current", CaptureResourceTable(nation->relationDeltaCurrent));
  object.Set("purchased_items_by_resource", CaptureResourceTable(nation->purchasedItemsByResource));
  object.Set("item_potentials", CaptureResourceTable(nation->itemPotentials));
  object.Set("unfilled_trade_turns_by_resource",
             CaptureResourceTable(nation->unfilledTradeTurnCountsByResource));
  object.Set("transported_items_by_resource",
             CaptureResourceTable(nation->transportedItemsByResource));
  object.Set("remembered_trade_offers_by_resource",
             CaptureResourceTable(nation->rememberedTradeOffersByResource));
  object.Set("aid_allocation_by_minor_nation",
             CaptureAidAllocationByMinorNation(nation->aidAllocationMatrix));
  object.Set("budget_pool_base", nation->budgetPoolBase);
  object.Set("budget_pool_delta", nation->budgetPoolDelta);
  object.Set("special_resource_trade_balance", nation->field910);
  object.Set("candidate_nation_flags",
             CaptureUnsignedByteArray(nation->candidateNationFlags, kNationSlotCount));
  object.Set("scenario_initialized", nation->scenarioInitFlag != 0 ? true : false);
  object.Set("turn_finished", nation->field904 != 0 ? true : false);
  object.Set("pending_action_status",
             CapturePendingActionStatus(nation->pendingActionStatus.byAction));
  object.Set("pending_action_payload_by_action", CapturePendingActionPayloads(nation->field8d6));
  object.Set("diplomacy_budget_base", nation->diplomacyBudgetBase);
  object.Set("escalation_counter", static_cast<int>(nation->escalationCounter));
  object.Set("pending_commitment_cost", nation->pendingCommitmentCost);
  object.Set("pressure_counter", static_cast<int>(nation->pressureCounter));
  object.Set("aid_allocation_total", nation->aidAllocationTotal);
  object.Set("colony_boycott_flags",
             CaptureUnsignedByteArray(nation->colonyBoycottFlags, kNationSlotCount));
  object.Set("military_expenses", nation->militaryExpenses960);
  return object.Release();
}

JSON_Value* CaptureNation(int slot) {
  TCountry* country = g_apTerrainTypeDescriptorTable[slot];
  if (country == 0) {
    return JsonNullValue();
  }

  JsonObject object;
  JsonObject common;
  common.Set("owner_nation", static_cast<int>(country->DecodeOwnerNationSlot()));
  common.Set("treasury", country->treasuryValue10);
  common.SetOptional("home_tile", country->homeTileIndex);
  common.Set("trade_policy_by_nation",
             CaptureShortArray(country->needLevelByNation, kNationSlotCount));
  object.Set("common", common.Release());

  if (slot < kMajorNationCount) {
    TGreatPower* nation = g_apNationStates[slot];
    object.Set("data", CaptureMajorNation(nation));
  } else {
    JsonObject data;
    data.Set("kind", "minor");
    object.Set("data", data.Release());
  }
  return object.Release();
}

JSON_Value* CaptureNations() {
  JsonArray nations;
  for (int slot = 0; slot < kNationSlotCount; ++slot) {
    nations.Add(CaptureNation(slot));
  }
  return nations.Release();
}

JSON_Value* CapturePopulation(const TPopulationMgr* population) {
  JsonObject object;
  object.Set("count", static_cast<int>(population->populationCount08));
  object.Set("count_float_bits", FloatBits(population->populationCountFloat0c));
  object.Set("strength", static_cast<int>(population->strength));
  object.Set("extra", static_cast<int>(population->extraAt1e));
  object.Set("phase_value", static_cast<int>(population->fieldAt20));
  object.Set("baseline_labor", CaptureLaborPool(population->baselineSlots10));
  object.Set("production_labor", CaptureLaborPool(population->productionSlots14));
  object.Set("pending_labor_delta", CaptureLaborPool(population->pendingDeltaSlots18));
  object.Set("predicted_need_by_resource",
             CaptureResourceTable(population->predictedNeedByResource22));
  return object.Release();
}

JSON_Value* CaptureCity(int slot) {
  TGreatPower* nation = g_apNationStates[slot];
  TCity* city = nation != 0 ? nation->city : 0;
  if (city == 0) {
    return JsonNullValue();
  }
  JsonObject object;
  object.Set("power_plant_upgrade_queued", city->powerPlantUpgradeQueuedFlag04 != 0 ? true : false);
  object.Set("food_substitution_count", static_cast<int>(city->foodSubstitutionCount06));
  object.Set("starvation_population_loss", static_cast<int>(city->starvationPopulationLoss08));
  object.Set("serialized_state", static_cast<int>(city->serializedState0a));
  object.Set("phase_counter", static_cast<int>(city->cityPhaseCounter0c));
  object.Set("military_recruit_count_by_kind",
             CaptureMilitaryUnitCounts(city->militaryRecruitCountByKind));
  object.Set("civilian_recruit_count_by_kind",
             CaptureCivilianUnitCounts(city->civilianRecruitCountByKind));
  object.Set("order_count_by_type", CaptureIndustryActionCounts(city->orderCountByType5c));
  object.Set("rolling_item_production_score", city->rollingItemProductionScore78);
  object.Set("low_production", city->lowProductionFlag7c != 0 ? true : false);
  object.Set("low_stock", city->lowStockFlag7d != 0 ? true : false);
  object.Set("reserved_by_type", CaptureResourceTable(city->reservedByType7e));
  if (city->homeTownMarkerB0 == 0) {
    object.SetNull("home_town_tile");
  } else {
    object.Set("home_town_tile", static_cast<int>(city->homeTownMarkerB0->tileIndex));
  }
  object.Set("power_available", static_cast<int>(city->powerAvailableB4));
  object.Set("stock_by_type", CaptureResourceTable(&city->cityStockCottonB6));
  object.Set("production_orders", CaptureShortArray(city->productionOrderTable1dc, 0x10));
  object.Set("production_accum", CaptureShortArray(city->productionAccum1fc, 0x10));
  object.Set("production_flags", CaptureUnsignedByteArray(city->productionFlags21c, 0x10));
  object.Set("production_current", CaptureShortArray(city->production22c, 0x10));
  object.Set("production_progress", CaptureShortArray(city->production24c, 0x10));
  object.Set("population_growth_penalty_ticks",
             static_cast<int>(city->populationGrowthPenaltyTicks26c));
  object.Set("unmet_resource_retries", CaptureResourceTable(city->unmetResourceRetryCount278));
  object.Set("consumed_production_input_by_type",
             CaptureResourceTable(city->consumedProductionInputByType2a6));
  object.Set("population", CapturePopulation(city->productionSummary1d8));
  return object.Release();
}

JSON_Value* CaptureCities() {
  JsonArray cities;
  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    cities.Add(CaptureCity(slot));
  }
  return cities.Release();
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
  JsonArray ships;
  for (TMapOrderChildLinkNode* link = links; link != 0; link = link->next) {
    JsonObject ship;
    ship.Set("ship", RuntimeShipIndex(static_cast<TShip*>(link->payload)));
    ship.Set("selected", link->active != 0 ? true : false);
    ships.Add(ship.Release());
  }
  return ships.Release();
}

JSON_Value* CaptureMilitaryUnits() {
  JsonArray units;
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    CIterator cursor(country->militaryUnitList44);
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      JsonObject object;
      object.Set("id", unit->persistentUnitId20);
      object.Set("nation", nationSlot);
      object.Set("unit_type", MilitaryUnitKindName(static_cast<int>(unit->orderType)));
      object.Set("stationed_province", static_cast<int>(unit->tileIndex06));
      object.Set("order", static_cast<int>(unit->unitOrder));
      object.Set("order_target", static_cast<int>(unit->orderTargetIndex0C));
      ASSERT(unit->ownerNationSlot18 >= 0 && unit->ownerNationSlot18 < kNationSlotCount);
      object.Set("owner_nation", static_cast<int>(unit->ownerNationSlot18));
      object.Set("roster_id", static_cast<int>(unit->unitRosterId1A));
      object.Set("registered", unit->militaryRegistrationFlag1C != 0 ? true : false);
      object.Set("order_target_tiles", CaptureShortArray(unit->orderTargetTiles28, 3));
      object.Set("order_target_mirrors", CaptureShortArray(unit->orderTargetTilesMirror2E, 3));
      object.Set("name", static_cast<LPCSTR>(unit->name24));
      object.Set("strength", static_cast<int>(unit->strength34));
      object.Set("era", static_cast<int>(unit->eraIndex36));
      object.Set("experience", static_cast<int>(unit->experiencePercent38));
      object.Set("battle_flags", static_cast<int>(unit->battleStateFlags3A));
      units.Add(object.Release());
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return units.Release();
}

JSON_Value* CaptureCivilianUnits() {
  JsonArray units;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    const int count =
        nation != 0 && nation->trackedObjectList != 0 ? nation->trackedObjectList->GetCount() : 0;
    for (int ordinal = 1; ordinal <= count; ++ordinal) {
      TCivUnit* unit =
          static_cast<TCivUnit*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      JsonObject object;
      object.Set("id", unit->persistentUnitId20);
      object.Set("nation", nationSlot);
      object.Set("unit_type", CivilianUnitKindName(static_cast<int>(unit->orderType)));
      object.SetOptional("tile", static_cast<int>(unit->tileIndex06));
      object.Set("order", CivilianWorkOrderName(unit->unitOrder));
      object.SetOptional("order_target", static_cast<int>(unit->orderTargetIndex0C));
      ASSERT(unit->ownerNationSlot18 >= 0 && unit->ownerNationSlot18 < kNationSlotCount);
      object.Set("owner_nation", static_cast<int>(unit->ownerNationSlot18));
      object.Set("roster_id", static_cast<int>(unit->unitRosterId1A));
      object.Set("registered", unit->militaryRegistrationFlag1C != 0 ? true : false);
      object.Set("remaining_turns", static_cast<int>(unit->remainingTurns24));
      units.Add(object.Release());
    }
  }
  return units.Release();
}

JSON_Value* CaptureShips() {
  JsonArray ships;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    JsonObject object;
    object.Set("ship_type", IndustryActionSlotName(static_cast<int>(ship->type)));
    object.Set("location", RuntimeZoneIndex(ship->location));
    object.SetOptional("task_force", RuntimeTaskForceIndex(ship->taskForce));
    object.Set("aggression", ship->aggression);
    ASSERT(ship->nation >= 0 && ship->nation < kNationSlotCount);
    object.Set("nation", static_cast<int>(ship->nation));
    object.Set("name", static_cast<LPCSTR>(ship->name));
    object.Set("strength", static_cast<int>(ship->strength));
    object.Set("experience", static_cast<int>(ship->experience));
    object.Set("selection", ship->selection);
    ships.Add(object.Release());
  }
  return ships.Release();
}

JSON_Value* CaptureTaskForceTarget(const TTaskForce* force) {
  JsonObject object;
  if (force->target == 0) {
    object.Set("kind", "none");
    return object.Release();
  }
  if (force->shipOrders == 5) {
    object.Set("kind", "province");
    object.Set("target", static_cast<int>(static_cast<Province*>(force->target)->GetIndex()));
  } else {
    object.Set("kind", "zone");
    object.Set("target", static_cast<int>(static_cast<TZone*>(force->target)->contextOrdinal14));
  }
  return object.Release();
}

JSON_Value* CaptureTaskForces() {
  JsonArray taskForces;
  TTaskForce* force = g_pNavyOrderManager != 0 ? g_pNavyOrderManager->orderQueueHead : 0;
  for (; force != 0; force = force->nextForce) {
    JsonObject object;
    object.Set("aggression", force->aggression);
    object.Set("order", force->shipOrders);
    object.Set("target", CaptureTaskForceTarget(force));
    object.Set("location", RuntimeZoneIndex(force->location));
    object.Set("nation", static_cast<int>(force->nation));
    object.Set("ship_counts", CaptureShortArray(force->shipCountsByToolbarSlot, 4));
    object.Set("ingot_tile", static_cast<int>(force->ingotTileIndex));
    object.SetOptional("flagship", RuntimeShipIndex(force->flagship));
    object.Set("ships", CaptureSelectedShips(force->shipList));
    taskForces.Add(object.Release());
  }
  return taskForces.Release();
}

JSON_Value* CaptureArmyMission(TArmyMission* mission) {
  JsonObject object;
  JsonArray equipage;
  JsonArray units;
  object.Set("present_location", static_cast<int>(mission->presentLocation14));
  for (int index = 0; index < 5; ++index) {
    equipage.Add(FloatBits(mission->requiredEquipageByClass[index]));
  }
  const int unitCount = mission->orderListAt18 != 0 ? mission->orderListAt18->GetCount() : 0;
  for (int ordinal = 1; ordinal <= unitCount; ++ordinal) {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(mission->orderListAt18->GetEntryByOrdinal(ordinal));
    units.Add(unit->persistentUnitId20);
  }
  object.Set("required_equipage_bits", equipage.Release());
  object.Set("units", units.Release());
  return object.Release();
}

JSON_Value* CaptureNavyMission(TNavyMission* mission) {
  JsonObject object;
  JsonArray equipage;
  object.Set("target_zone", RuntimeZoneIndex(mission->missionTargetZone));
  object.Set("resolved_port_zone", RuntimeZoneIndex(mission->resolvedPortZone));
  object.SetOptional("selected_ship", RuntimeShipIndex(mission->selectedOrder1c));
  object.SetOptional("task_force", RuntimeTaskForceIndex(mission->taskForce20));
  object.Set("state", mission->navyState28);
  for (int index = 0; index < 4; ++index) {
    equipage.Add(FloatBits(mission->requiredShipEquipageByCategory[index]));
  }
  object.Set("required_equipage_bits", equipage.Release());
  object.Set("ships", CaptureSelectedShips(mission->orderList24));
  return object.Release();
}

JSON_Value* CaptureAttackMission(TAttackProvinceMission* mission) {
  JsonObject object;
  object.Set("army", CaptureArmyMission(mission));
  object.Set("target_province", static_cast<int>(mission->targetProvince30));
  object.Set("amassing_province", static_cast<int>(mission->amassingProvince32));
  return object.Release();
}

JSON_Value* CaptureMissionData(TMission* mission) {
  if (mission->IsKindOf(RUNTIME_CLASS(TInvadeMission))) {
    TInvadeMission* invade = static_cast<TInvadeMission*>(mission);
    JsonObject object;
    object.Set("kind", "invade");
    object.Set("attack", CaptureAttackMission(invade));
    object.Set("beachhead", invade->beachhead34 != 0 ? CaptureNavyMission(invade->beachhead34)
                                                     : JsonNullValue());
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TAttackProvinceMission))) {
    JsonObject object(CaptureAttackMission(static_cast<TAttackProvinceMission*>(mission)));
    object.Set("kind", "attack_province");
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TDefendProvinceMission))) {
    JsonObject object(CaptureArmyMission(static_cast<TArmyMission*>(mission)));
    object.Set("kind", "defend_province");
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBlockadePortMission))) {
    TBlockadePortMission* blockade = static_cast<TBlockadePortMission*>(mission);
    JsonObject object;
    object.Set("kind", "blockade_port");
    object.Set("navy", CaptureNavyMission(blockade));
    object.Set("port_zone", RuntimeZoneIndex(blockade->portZoneContext3c));
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBeachheadMission))) {
    JsonObject object(CaptureNavyMission(static_cast<TNavyMission*>(mission)));
    object.Set("kind", "beachhead");
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TControlSeaZoneMission))) {
    JsonObject object(CaptureNavyMission(static_cast<TNavyMission*>(mission)));
    object.Set("kind", "control_sea_zone");
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TEscortMission))) {
    JsonObject object(CaptureNavyMission(static_cast<TNavyMission*>(mission)));
    object.Set("kind", "escort");
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TScatteredShipsMission))) {
    JsonObject object(CaptureNavyMission(static_cast<TNavyMission*>(mission)));
    object.Set("kind", "scattered_ships");
    return object.Release();
  }
  return JsonNullValue();
}

JSON_Value* CaptureMissions() {
  JsonArray missions;
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
      JsonObject object;
      object.Set("nation", nationSlot);
      object.Set("queue_index", queueOrdinal - 1);
      object.Set("data", CaptureMissionData(mission));
      object.Set("source_nation", static_cast<int>(mission->nationId04));
      object.Set("path_marker", static_cast<int>(mission->pathMarker06));
      object.Set("state", static_cast<unsigned int>(mission->state08));
      object.Set("importance_bits", FloatBits(mission->importanceScore0c));
      object.Set("marker", static_cast<unsigned int>(mission->marker11));
      missions.Add(object.Release());
    }
  }
  return missions.Release();
}

JSON_Value* CaptureTaggedValues(TSortedByRelationshipList* queue) {
  JsonArray values;
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JsonObject object;
    object.Set("tag", static_cast<int>(record[0]));
    object.Set("value", static_cast<int>(record[1]));
    values.Add(object.Release());
  }
  return values.Release();
}

JSON_Value* CaptureTurnSummary(TSortedByRelationshipList* queue) {
  JsonArray summaries;
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TurnOrderDispatchPacket* packet =
        static_cast<TurnOrderDispatchPacket*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JsonObject object;
    object.Set("turn_tick", static_cast<int>(packet->turnTick));
    object.Set("order_kind", static_cast<int>(packet->orderKind));
    object.Set("payload", static_cast<int>(packet->payload));
    object.Set("flags", static_cast<int>(packet->flags));
    summaries.Add(object.Release());
  }
  return summaries.Release();
}

JSON_Value* CaptureTurnStartEvents(TSortedList* queue) {
  JsonArray events;
  const int count = queue != 0 ? queue->GetCount() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TTurnStartEvent* event = static_cast<TTurnStartEvent*>(queue->GetEntryByOrdinal(ordinal));
    CRuntimeClass* runtimeClass = event != 0 ? event->GetRuntimeClass() : 0;
    JsonObject object;
    object.Set("class", runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown");
    object.Set("tag", event != 0 ? event->eventTag04 : 0);
    if (event != 0 && event->IsKindOf(RUNTIME_CLASS(TLandSaleEvent))) {
      TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
      JsonObject landSaleObject;
      landSaleObject.Set("province", static_cast<int>(landSale->tileIndex08));
      landSaleObject.Set("nation", static_cast<int>(landSale->nationCode0a));
      object.Set("land_sale", landSaleObject.Release());
    } else {
      object.Set("land_sale", JsonNullValue());
    }
    events.Add(object.Release());
  }
  return events.Release();
}

JSON_Value* CaptureNationPendingWork(TGreatPower* nation) {
  JsonObject object;
  object.Set("turn_events", CaptureTaggedValues(nation != 0 ? nation->turnEventQueue : 0));
  object.Set("proposals", CaptureTaggedValues(nation != 0 ? nation->proposalQueue : 0));
  object.Set("turn_summary", CaptureTurnSummary(nation != 0 ? nation->turnSummaryQueue : 0));
  object.Set("turn_start_events",
             CaptureTurnStartEvents(nation != 0 ? nation->missionNodeQueue : 0));
  return object.Release();
}

JSON_Value* CapturePending() {
  JsonObject object;
  JsonArray nations;
  JsonArray transitions;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    nations.Add(CaptureNationPendingWork(g_apNationStates[nationSlot]));
  }
  TSortedPtrList* queue = g_pDiplomacyTurnStateManager != 0
                              ? g_pDiplomacyTurnStateManager->pendingWarTransitionQueue
                              : 0;
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* pair = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    JsonObject transition;
    transition.Set("first", static_cast<int>(pair[0]));
    transition.Set("second", static_cast<int>(pair[1]));
    transitions.Add(transition.Release());
  }
  object.Set("nations", nations.Release());
  object.Set("war_transitions", transitions.Release());
  return object.Release();
}

} // namespace

bool BuildRuntimeGameState(const RuntimeRun& run, JSON_Value** state) {
  if (state == 0 || g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 ||
      g_pSimMgr == 0 || g_pTradeMgr == 0) {
    return false;
  }

  JsonObject object;
  object.Set("turn", CaptureTurn(run));
  object.Set("persistent_unit_id_counter", g_pSimMgr->field_64);
  object.Set("world", CaptureWorld());
  object.Set("rng", CaptureRng());
  object.Set("market", CaptureMarket());
  object.Set("nations", CaptureNations());
  object.Set("cities", CaptureCities());
  object.Set("military_units", CaptureMilitaryUnits());
  object.Set("civilian_units", CaptureCivilianUnits());
  object.Set("ships", CaptureShips());
  object.Set("task_forces", CaptureTaskForces());
  object.Set("missions", CaptureMissions());
  object.Set("pending", CapturePending());
  *state = object.Release();
  return true;
}

bool CaptureGameState(RuntimeRun& run, const char* name) {
  if (name == 0) {
    return false;
  }
  JSON_Value* state = 0;
  if (!BuildRuntimeGameState(run, &state)) {
    return false;
  }
  run.SetCapture(name, state);
  return true;
}

void CaptureRuntimeGameState(RuntimeRun& run) {
  if (!run.RequestsCapture(kRuntimeCaptureGameState) || run.HasCapture("game_state") ||
      run.HasCapture("after")) {
    return;
  }
  if (!CaptureGameState(run, "game_state")) {
    run.RecordAssertion("capture.game_state", "the semantic game-state capture is unavailable",
                        true);
  }
}
