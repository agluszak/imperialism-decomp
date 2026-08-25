#include "RuntimeGameStateCapture.h"

#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/city/TTown.h"
#include "game/city/TCapacityOrder.h"
#include "game/city/TExpansionOrder.h"
#include "game/city/TFoodProcessingOrder.h"
#include "game/city/TItemOrder.h"
#include "game/city/TOrItemOrder.h"
#include "game/city/TPopGrowthOrder.h"
#include "game/city/TPopulationMgr.h"
#include "game/city/TPowerPlantOrder.h"
#include "game/city/TShipOrder.h"
#include "game/city/TTrainingOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/city_ui/TLongintList.h"
#include "game/civilian_domain_types.h"
#include "game/debug/TLaborPool.h"
#include "game/diplomacy_domain_types.h"
#include "game/military_domain_types.h"
#include "game/assets/TAssetMgr.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/ui_core_globals.h"
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
#include "game/military/TArmyMgr.h"
#include "game/military/TArmyMission.h"
#include "game/military/TAttackProvinceMission.h"
#include "game/military/TCivUnit.h"
#include "game/military/TDefendProvinceMission.h"
#include "game/military/TInvadeMission.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_ui/TDefenseMinister.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/nation/TForeignMinister.h"
#include "game/nation/TForeignMinisterPersonalities.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/nation/TLandSaleEvent.h"
#include "game/nation/TMinor.h"
#include "game/nation/TTurnStartEvent.h"
#include "game/navy/TAdmiral.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/globals/navy_globals.h"
#include "game/tactical_ui/TCityTask.h"
#include "game/tactical_ui/TShipBuildingTask.h"
#include "game/tactical_ui/TTaskList.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/CIterator.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TPortZone.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VC5 libcmt rand.obj stores the thread-local LCG state at +0x14 in the block returned
// by _getptd. This test-only observation is backed by the vendored rand.obj disassembly;
// production source continues to use the ordinary CRT rand/srand API.
extern "C" void* __cdecl _getptd(void);

namespace {

void FailSemanticCapture(const char* detail) {
  fprintf(stderr, "runtime semantic capture invariant failed: %s\n", detail);
  fflush(stderr);
  exit(EXIT_FAILURE);
}

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

const char* const kShipTypeNames[kIndustryActionSlotCount] = {
    "no_ship",       "trader",          "indiaman",    "frigate",      "ship_of_the_line",
    "paddlewheeler", "clipper",         "raider",      "ironclad",     "advanced_ironclad",
    "freighter",     "armored_cruiser", "dreadnought", "battlecruiser"};

const char* const kIndustryActionSlotNames[kIndustryActionSlotCount] = {
    "textile_mill",      "clothing_factory", "steel_mill",      "metalworks", "lumber_mill",
    "furniture_factory", "oil_refinery",     "shipyard",        "armory",     "trade_school",
    "university",        "power_plant",      "food_processing", "warehouse"};

const char* const kTerrainNames[8] = {"plains", "forest", "hills",  "mountain",
                                      "swamp",  "water",  "desert", "farmland"};

const char* const kResourceNames[kResourceKindCount] = {
    "cotton", "wool",   "timber", "coal",  "iron",      "horses",   "oil",       "food",
    "fabric", "lumber", "paper",  "steel", "fuel",      "clothing", "furniture", "hardware",
    "arms",   "grain",  "fruit",  "fish",  "livestock", "gems",     "gold"};

const char* InterNationNewsKindName(InterNationEventKind eventKind) {
  switch (eventKind) {
  case kInterNationEventWarDeclaredBySubject:
    return "war_declared_by_subject";
  case kInterNationEventWarDeclaredAgainstSubject:
    return "war_declared_against_subject";
  case kInterNationEventPeaceTreatyAccepted:
    return "peace_treaty_accepted";
  case kInterNationEventJoinEmpireAccepted:
    return "join_empire_accepted";
  case kInterNationEventAllianceAccepted:
    return "alliance_accepted";
  case kInterNationEventNonAggressionPactAccepted:
    return "non_aggression_pact_accepted";
  case kInterNationEventPeaceTreatyRejected:
    return "peace_treaty_rejected";
  case kInterNationEventJoinEmpireRejected:
    return "join_empire_rejected";
  case kInterNationEventAllianceRejected:
    return "alliance_rejected";
  case kInterNationEventNonAggressionPactRejected:
    return "non_aggression_pact_rejected";
  case kInterNationEventTradeConsulateEstablished:
    return "trade_consulate_established";
  case kInterNationEventEmbassyEstablished:
    return "embassy_established";
  case kInterNationEventMinorEmpireAffiliationChanged:
    return "minor_empire_affiliation_changed";
  case kInterNationEventMinorTerritoryRelationshipAffected:
    return "minor_territory_relationship_affected";
  case kInterNationEventPeaceRelationshipPropagated:
    return "peace_relationship_propagated";
  case kInterNationEventWarWithIndependentMinor:
    return "war_with_independent_minor";
  case kInterNationEventAllianceRelationshipEstablished:
    return "alliance_relationship_established";
  case kInterNationEventNationJoinedEmpire:
    return "nation_joined_empire";
  case kInterNationEventNationJoinedWar:
    return "nation_joined_war";
  case kInterNationEventNationTransferred:
    return "nation_transferred";
  default:
    FailSemanticCapture("shared newspaper queue contains an unknown inter-nation event kind");
    return "";
  }
}

int RequiredNewspaperMajorNation(int nation) {
  if (nation < 0 || nation >= kMajorNationCount) {
    FailSemanticCapture("shared newspaper event subject is outside the major-nation range");
  }
  return nation;
}

JSON_Value* CaptureNewspaperNationMask(int source) {
  const unsigned int validBits = (1u << kNationSlotCount) - 1u;
  const unsigned int sourceBits = static_cast<unsigned int>(source);
  if ((sourceBits & ~validBits) != 0) {
    FailSemanticCapture("shared newspaper event mask contains bits outside the nation table");
  }

  JsonArray nations;
  for (int nation = 0; nation < kNationSlotCount; ++nation) {
    nations.Add((sourceBits & (1u << nation)) != 0);
  }
  return nations.Release();
}

const char* DifficultyName(int value) {
  if (value < 0 || value >= 5) {
    FailSemanticCapture("difficulty is outside its semantic range");
  }
  return kDifficultyNames[value];
}

const char* CivilianUnitKindName(int value) {
  if (value < 0 || value >= kCivilianUnitKindCount) {
    FailSemanticCapture("civilian unit kind is outside its semantic range");
  }
  return kCivilianUnitKindNames[value];
}

const char* TerrainName(int value) {
  if (value < 0 || value >= 8) {
    FailSemanticCapture("terrain kind is outside its semantic range");
  }
  return kTerrainNames[value];
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
    FailSemanticCapture("civilian work order has no semantic representation");
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

const char* const kSemanticHexDirectionNames[kStrategicHexDirectionCount] = {
    "NorthEast", "East", "SouthEast", "SouthWest", "West", "NorthWest"};

void SetDirectionalLinks(JsonObject& object, const char* name, unsigned char flags) {
  char text[64];
  text[0] = '\0';
  if ((flags & ~0x3f) != 0) {
    FailSemanticCapture("directional-link flags contain unknown bits");
  }

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
  if (value < 0 || value >= kMilitaryUnitKindCount) {
    FailSemanticCapture("military unit kind is outside its semantic range");
  }
  return kMilitaryUnitKindNames[value];
}

const char* ShipTypeName(int value) {
  if (value < 0 || value >= kIndustryActionSlotCount) {
    FailSemanticCapture("ship type is outside its semantic range");
  }
  return kShipTypeNames[value];
}

const char* IndustryActionSlotName(int value) {
  if (value < 0 || value >= kIndustryActionSlotCount) {
    FailSemanticCapture("industry action slot is outside its semantic range");
  }
  return kIndustryActionSlotNames[value];
}

JSON_Value* CaptureShortArray(const short* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    array.Add(static_cast<int>(values[index]));
  }
  return array.Release();
}

JSON_Value* CaptureOptionalShortArray(const short* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    if (values[index] < -1) {
      FailSemanticCapture("optional short is below the -1 sentinel");
    }
    if (values[index] == -1) {
      array.AddNull();
    } else {
      array.Add(static_cast<int>(values[index]));
    }
  }
  return array.Release();
}

void AddOptionalMajorNation(JsonArray& array, int value) {
  if (value == -1) {
    array.AddNull();
  } else if (value >= 0 && value < kMajorNationCount) {
    array.Add(value);
  } else {
    FailSemanticCapture("optional major-nation slot is outside its semantic range");
  }
}

void SetOptionalMajorNation(JsonObject& object, const char* name, int value) {
  if (value == -1) {
    object.SetNull(name);
  } else if (value >= 0 && value < kMajorNationCount) {
    object.Set(name, value);
  } else {
    FailSemanticCapture("optional major-nation slot is outside its semantic range");
  }
}

JSON_Value* CaptureOptionalMajorNationArray(const short* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    AddOptionalMajorNation(array, values[index]);
  }
  return array.Release();
}

JSON_Value* CaptureOptionalMajorNationByteArray(const signed char* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    AddOptionalMajorNation(array, values[index]);
  }
  return array.Release();
}

const char* DiplomaticRelationshipName(short value) {
  switch (value) {
  case kDiplomacyRelationshipAlliance:
    return "alliance";
  case kDiplomacyRelationshipNonAggressionPact:
    return "non_aggression_pact";
  case kDiplomacyRelationshipPeace:
    return "peace";
  case kDiplomacyRelationshipJoinedEmpire:
    return "joined_empire";
  case kDiplomacyRelationshipWar:
    return "war";
  default:
    FailSemanticCapture("diplomatic relationship is outside its semantic range");
    return "";
  }
}

const char* DiplomaticMissionLevelName(short value) {
  switch (value) {
  case kDiplomaticMissionNone:
    return "none";
  case kDiplomaticMissionTradeConsulate:
    return "trade_consulate";
  case kDiplomaticMissionEmbassy:
    return "embassy";
  default:
    FailSemanticCapture("diplomatic mission level is outside its semantic range");
    return "";
  }
}

JSON_Value* CaptureNationPairShortTable(const short* values) {
  JsonArray rows;
  for (int source = 0; source < kNationSlotCount; ++source) {
    rows.Add(CaptureShortArray(&values[source * kNationSlotCount], kNationSlotCount));
  }
  return rows.Release();
}

JSON_Value* CaptureNationPairRelationshipTable(const short* values) {
  JsonArray rows;
  for (int source = 0; source < kNationSlotCount; ++source) {
    JsonArray row;
    for (int target = 0; target < kNationSlotCount; ++target) {
      row.Add(DiplomaticRelationshipName(values[source * kNationSlotCount + target]));
    }
    rows.Add(row.Release());
  }
  return rows.Release();
}

JSON_Value* CaptureNationPairTurnTable(const short* values) {
  JsonArray rows;
  for (int source = 0; source < kNationSlotCount; ++source) {
    JsonArray row;
    for (int target = 0; target < kNationSlotCount; ++target) {
      int value = values[source * kNationSlotCount + target];
      if (value < -1) {
        FailSemanticCapture("relationship turn stamp is below the -1 sentinel");
      } else if (value == -1) {
        row.AddNull();
      } else {
        row.Add(value);
      }
    }
    rows.Add(row.Release());
  }
  return rows.Release();
}

JSON_Value* CaptureNationPairMissionTable(const short* values) {
  JsonArray rows;
  for (int source = 0; source < kNationSlotCount; ++source) {
    JsonArray row;
    for (int target = 0; target < kNationSlotCount; ++target) {
      row.Add(DiplomaticMissionLevelName(values[source * kNationSlotCount + target]));
    }
    rows.Add(row.Release());
  }
  return rows.Release();
}

JSON_Value* CaptureDiplomacy() {
  TDiplomacyMgr* manager = g_pDiplomacyTurnStateManager;
  ASSERT(manager != 0);

  JsonObject object;
  object.Set("standings", CaptureNationPairShortTable(manager->relationStandingScores));
  object.Set("relationships",
             CaptureNationPairRelationshipTable(manager->relationPropagationMatrix));
  object.Set("relationship_turns", CaptureNationPairTurnTable(manager->relationTurnStampMatrix));
  object.Set("influence_thresholds",
             CaptureShortArray(manager->relationCodeMatrix, kDiplomacyPairMatrixEntries));
  object.Set("influence_sides", CaptureOptionalMajorNationByteArray(
                                    manager->pendingPolicyCodeMatrix, kDiplomacyPairMatrixEntries));
  object.Set("last_diplomatic_effort_turn", static_cast<int>(manager->lastDiplomaticEffortTurn));
  object.Set("mission_levels", CaptureNationPairMissionTable(manager->relationSideEffectMatrix));

  JsonObject congress;
  SetOptionalMajorNation(congress, "chairman", manager->congressLeadership.chairmanNationSlot);
  SetOptionalMajorNation(congress, "counterpart",
                         manager->congressLeadership.counterpartNationSlot);
  congress.Set("chairman_support", static_cast<int>(manager->congressSupport.chairmanSupportCount));
  congress.Set("counterpart_support",
               static_cast<int>(manager->congressSupport.counterpartSupportCount));
  congress.Set("neutral_support", static_cast<int>(manager->congressSupport.neutralCount));
  object.Set("congress", congress.Release());

  object.Set("special_relation_sources",
             CaptureOptionalMajorNationArray(manager->specialRelationSourceSlots,
                                             kNationSlotCount - kMajorNationCount));
  object.Set("special_relation_targets",
             CaptureOptionalMajorNationArray(manager->specialRelationTargetSlots,
                                             kNationSlotCount - kMajorNationCount));
  SetOptionalMajorNation(object, "last_processed_nation", manager->lastProcessedNationSlot);
  object.Set("proposal_mode_raw", static_cast<int>(manager->proposalArrayMode));
  return object.Release();
}

JSON_Value* CaptureOptionalResourceArray(const signed char* values, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    if (values[index] < -1 || values[index] >= kResourceKindCount) {
      FailSemanticCapture("optional resource code is outside its semantic range");
    }
    if (values[index] == -1) {
      array.AddNull();
    } else {
      array.Add(kResourceNames[values[index]]);
    }
  }
  return array.Release();
}

void AppendFlagName(char* text, const char* name) {
  if (text[0] != '\0') {
    strcat(text, " | ");
  }
  strcat(text, name);
}

const char* CaptureTileFlags(unsigned short source, char* text) {
  const unsigned short bits[7] = {0x01, 0x02, 0x08, 0x20, 0x22, 0x21, 0x37};
  const char* const names[7] = {
      "BASE_TRANSPORT",   "RECRUITMENT_RESERVED",  "PROVINCE_CAPITAL_FORTIFICATION",
      "CITY_MARKER",      "PROVINCE_ANCHOR_STATE", "MINOR_HOME_STATE",
      "PLACED_CITY_STATE"};
  unsigned short remaining = source;
  text[0] = '\0';
  for (int index = 0; index < 7; ++index) {
    if ((source & bits[index]) == bits[index] && (remaining & bits[index]) != 0) {
      AppendFlagName(text, names[index]);
      remaining = static_cast<unsigned short>(remaining & ~bits[index]);
    }
  }
  if (remaining != 0) {
    char unknown[16];
    sprintf(unknown, "0x%x", static_cast<unsigned int>(remaining));
    AppendFlagName(text, unknown);
  }
  return text;
}

JSON_Value* CaptureShipTypeCounts(const short* values) {
  JsonObject object;
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    object.Set(kShipTypeNames[slot], static_cast<int>(values[slot]));
  }
  return object.Release();
}

JSON_Value* CaptureNationCapacities(const TGreatPower* nation) {
  JsonObject object;
  object.Set("available_merchant", static_cast<int>(nation->availableMerchantCapacity));
  object.Set("trade_offer", static_cast<int>(nation->merchantCapacity));
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

    if (entry < -1) {
      FailSemanticCapture("diplomacy grant is below the -1 sentinel");
    }
    JsonObject grant;
    grant.Set("amount", static_cast<int>(entry & 0x3fff));
    grant.Set("recurring", (entry & 0x4000) != 0);
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
    FailSemanticCapture("diplomacy policy has no semantic representation");
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

JSON_Value* CaptureTradeCommodityTable(const short* values) {
  JsonObject table;
  for (int index = 0; index < kResourceManufacturedEnd; ++index) {
    table.Set(kResourceNames[index], static_cast<int>(values[index]));
  }
  return table.Release();
}

JSON_Value* CaptureProcessedTradeCommodityTable(const short* values) {
  JsonObject table;
  for (int index = 0; index < 6; ++index) {
    table.Set(kResourceNames[kResourceFood + index], static_cast<int>(values[index]));
  }
  return table.Release();
}

JSON_Value* RuntimeJsonString(const char* value);

JSON_Value* CaptureOptionalTradeCommodity(short resourceKind) {
  if (resourceKind == -10) {
    return JsonNullValue();
  }
  if (resourceKind < kResourceCotton || resourceKind >= kResourceManufacturedEnd) {
    FailSemanticCapture("trade commodity is outside the semantic range");
  }
  return RuntimeJsonString(kResourceNames[resourceKind]);
}

JSON_Value* CaptureOptionalManufacturedTradeCommodity(short resourceKind) {
  if (resourceKind == -10) {
    return JsonNullValue();
  }
  if (resourceKind < kResourceClothing || resourceKind >= kResourceManufacturedEnd) {
    FailSemanticCapture("manufactured trade request is outside the semantic range");
  }
  return RuntimeJsonString(kResourceNames[resourceKind]);
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
    rowObject.Set("current_offer_by_nation",
                  CaptureShortArray(&row.tradeOfferCells[0], kNationSlotCount));
    JsonArray maximumOfferRow;
    const short* maximumByNation = &row.tradeOfferCells[46];
    for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
      // Slot 22 is the final serialized short even though it crosses the declared cell array
      // into the following row/padding in the retail runtime layout.
      const short value = maximumByNation[nationSlot];
      if (value < 0) {
        FailSemanticCapture("trade maximum offer is negative");
      }
      maximumOfferRow.Add(static_cast<int>(value));
    }
    rowObject.Set("maximum_offer_by_nation", maximumOfferRow.Release());
    rows.Set(kResourceNames[resource], rowObject.Release());
  }
  market.Set("rows", rows.Release());
  return market.Release();
}

JSON_Value* CaptureTechnology() {
  const int kAdvancedIronWorkingTechId = 0x0f;
  const int kOilDrillingTechId = TTechMgr::kProductionOrderTechId;
  const unsigned char advancedIronWorking = g_pTechMgr->resourceTypeEnabled19d[8];
  const unsigned char marineEngineering = g_pTechMgr->resourceTypeEnabled19d[0xb];
  if (advancedIronWorking > 1 || marineEngineering > 1) {
    FailSemanticCapture("technology resource-type flag is not boolean");
  }
  JsonObject technology;
  JsonArray scheduledUnlockTurnByTechnology;
  JsonArray globalUnlocksByTechnology;
  for (int technologyId = 0; technologyId < 0x1d; ++technologyId) {
    scheduledUnlockTurnByTechnology.Add(
        static_cast<int>(g_pTechMgr->prioritySlots04[technologyId]));
    const unsigned char unlocked = g_pTechMgr->perTechUnlockFlag180[technologyId];
    if (unlocked > 1) {
      FailSemanticCapture("global technology unlock flag is not boolean");
    }
    globalUnlocksByTechnology.Add(unlocked != 0);
  }
  JsonArray industryEnabledBySlot;
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    const unsigned char enabled = g_pTechMgr->resourceTypeEnabled19d[slot];
    if (enabled > 1) {
      FailSemanticCapture("technology industry-enabled flag is not boolean");
    }
    industryEnabledBySlot.Add(enabled != 0);
  }
  JsonArray militaryUnitAbilityActiveByNation;
  JsonArray selectedShipTypesByNation;
  JsonArray cityCapabilitiesByNation;
  JsonArray researchStatusByNation;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    const TTechMgr::OrderCapRow& technologyStatus = g_pTechMgr->orderCapRows277[nationSlot];
    const unsigned char advancedIronWorkingStatus =
        technologyStatus.techStatusByTechId[kAdvancedIronWorkingTechId];
    const unsigned char oilDrillingStatus = technologyStatus.techStatusByTechId[kOilDrillingTechId];
    if (advancedIronWorkingStatus > 2 || oilDrillingStatus > 2) {
      FailSemanticCapture("major-nation city technology status is invalid");
    }
    const int civilianTechIds[6] = {5, 6, 11, 12, 22, 23};
    for (int index = 0; index < 6; ++index) {
      if (technologyStatus.techStatusByTechId[civilianTechIds[index]] > 2) {
        FailSemanticCapture("major-nation civilian technology status is invalid");
      }
    }

    JsonArray researchStatus;
    for (int technologyId = 0; technologyId < 0x1d; ++technologyId) {
      const unsigned char status = technologyStatus.techStatusByTechId[technologyId];
      if (status > 2) {
        FailSemanticCapture("major-nation technology status is invalid");
      }
      const char* const names[3] = {"not_started", "pending", "researched"};
      researchStatus.Add(names[status]);
    }
    researchStatusByNation.Add(researchStatus.Release());

    JsonObject abilityActiveByUnitType;
    for (int unitType = 0; unitType < kMilitaryUnitKindCount; ++unitType) {
      const unsigned char active =
          g_pTechMgr->abilityActiveRows395[nationSlot].abilityActiveById[unitType];
      if (active > 1) {
        FailSemanticCapture("major-nation military-unit ability flag is not boolean");
      }
      abilityActiveByUnitType.Set(MilitaryUnitKindName(unitType), active != 0);
    }
    militaryUnitAbilityActiveByNation.Add(abilityActiveByUnitType.Release());

    JsonObject selectedShipTypes;
    for (int shipType = 0; shipType < kIndustryActionSlotCount; ++shipType) {
      const unsigned char selected =
          g_pTechMgr->capRowsB333[nationSlot].selectedByResourceType[shipType];
      if (selected > 1) {
        FailSemanticCapture("major-nation selected ship-type flag is not boolean");
      }
      selectedShipTypes.Set(kShipTypeNames[shipType], selected != 0);
    }
    selectedShipTypesByNation.Add(selectedShipTypes.Release());

    JsonObject cityCapabilities;
    cityCapabilities.Set("advanced_iron_working", advancedIronWorkingStatus == 2);
    cityCapabilities.Set("oil_drilling", oilDrillingStatus == 2);

    JsonObject university;
    JsonObject available;
    const TTechMgr::UniversityRecruitmentAvailabilityRow& recruitmentAvailability =
        g_pTechMgr->universityRecruitmentAvailabilityByNation467[nationSlot];
    for (int civilianKind = 0; civilianKind < kCivilianUnitKindCount; ++civilianKind) {
      const unsigned char value = recruitmentAvailability.availableByCategory[civilianKind];
      if (value > 1) {
        FailSemanticCapture("major-nation university availability is not boolean");
      }
      available.Set(kCivilianUnitKindNames[civilianKind], value != 0);
    }

    JsonObject requirementLevels;
    for (int resource = 0; resource < kResourceKindCount; ++resource) {
      const short level = g_pTechMgr->capabilityValueByNationAndResource[nationSlot][resource];
      if (level < 0 || level > 3) {
        FailSemanticCapture("major-nation university requirement level is outside 0..3");
      }
      requirementLevels.Set(kResourceNames[resource], static_cast<int>(level));
    }
    university.Set("available", available.Release());
    university.Set("requirement_levels", requirementLevels.Release());
    cityCapabilities.Set("university", university.Release());
    JsonObject primaryTerrain;
    primaryTerrain.Set("hills", technologyStatus.techStatusByTechId[12] == 2);
    primaryTerrain.Set("mountain", technologyStatus.techStatusByTechId[23] == 2);
    primaryTerrain.Set("swamp", technologyStatus.techStatusByTechId[6] == 2);
    cityCapabilities.Set("primary_civilian_distance_terrain", primaryTerrain.Release());
    cityCapabilities.Set("secondary_civilian_hills", technologyStatus.techStatusByTechId[11] == 2);
    cityCapabilities.Set("secondary_civilian_swamp", technologyStatus.techStatusByTechId[5] == 2);
    cityCapabilities.Set("fort_level_cap", g_pTechMgr->GetNationFortLevelCap(nationSlot));
    cityCapabilitiesByNation.Add(cityCapabilities.Release());
  }
  JsonArray selectedCapabilitySlotsByNation;
  for (int capabilityNation = 0; capabilityNation < kMajorNationCount; ++capabilityNation) {
    selectedCapabilitySlotsByNation.Add(
        CaptureShortArray(g_pTechMgr->nationCapRows1e8[capabilityNation].slots, 10));
  }
  technology.Set("advanced_iron_working", advancedIronWorking != 0);
  technology.Set("marine_engineering", marineEngineering != 0);
  technology.Set("scheduled_unlock_turn_by_technology", scheduledUnlockTurnByTechnology.Release());
  technology.Set("global_unlocks_by_technology", globalUnlocksByTechnology.Release());
  technology.Set("research_status_by_nation", researchStatusByNation.Release());
  technology.Set("industry_enabled_by_slot", industryEnabledBySlot.Release());
  technology.Set("military_unit_ability_active_by_nation",
                 militaryUnitAbilityActiveByNation.Release());
  technology.Set("selected_ship_types_by_nation", selectedShipTypesByNation.Release());
  technology.Set("selected_capability_slots", selectedCapabilitySlotsByNation.Release());
  technology.Set("city_capabilities_by_nation", cityCapabilitiesByNation.Release());
  technology.Set("navy_growth_ship_type", ShipTypeName(g_pTechMgr->activeZoneIndex1d4));
  return technology.Release();
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

int ValidateLiveZoneContextCount() {
  unsigned char seen[0x70];
  memset(seen, 0, sizeof(seen));
  int liveCount = 0;
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    if (liveCount >= static_cast<int>(sizeof(seen))) {
      FailSemanticCapture("live map-action context count exceeds the AI state capacity");
    }
    const int ordinal = static_cast<int>(zone->contextOrdinal14);
    if (ordinal < 0 || ordinal >= static_cast<int>(sizeof(seen))) {
      FailSemanticCapture("live map-action context ordinal is outside the AI state capacity");
    }
    if (seen[ordinal] != 0) {
      FailSemanticCapture("live map-action context ordinal is duplicated");
    }
    seen[ordinal] = 1;
    ++liveCount;
  }
  for (int ordinal = 0; ordinal < liveCount; ++ordinal) {
    if (seen[ordinal] == 0) {
      FailSemanticCapture("live map-action context ordinals are not contiguous");
    }
  }
  return liveCount;
}

JSON_Value* CaptureAiZoneTargets(TGreatPower* nation) {
  if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
    return JsonNullValue();
  }

  TAutoGreatPower* automaticNation = static_cast<TAutoGreatPower*>(nation);
  const int liveCount = ValidateLiveZoneContextCount();
  JsonArray targets;
  int ordinal;
  for (ordinal = 0; ordinal < liveCount; ++ordinal) {
    switch (automaticNation->portZoneStateFlags[ordinal]) {
    case 0:
      targets.Add("unmarked");
      break;
    case 1:
      targets.Add("candidate");
      break;
    case 2:
      targets.Add("mission_queued");
      break;
    default:
      FailSemanticCapture("live AI zone target has an invalid state");
    }
  }
  for (ordinal = liveCount; ordinal < static_cast<int>(sizeof(automaticNation->portZoneStateFlags));
       ++ordinal) {
    if (automaticNation->portZoneStateFlags[ordinal] != 0) {
      FailSemanticCapture("unused AI zone target has a nonzero state");
    }
  }
  return targets.Release();
}

JSON_Value* CaptureAiProvinceTargets(TGreatPower* nation) {
  if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
    return JsonNullValue();
  }

  TAutoGreatPower* automaticNation = static_cast<TAutoGreatPower*>(nation);
  JsonArray targets;
  for (int province = 0; province < 0x180; ++province) {
    switch (automaticNation->mapNodeStateFlags[province]) {
    case 0:
      targets.Add("unmarked");
      break;
    case 1:
      targets.Add("candidate");
      break;
    case 2:
      targets.Add("mission_queued");
      break;
    default:
      FailSemanticCapture("AI province target has an invalid state");
    }
  }
  return targets.Release();
}

int RequiredZoneOrdinal(TZone* zone, int liveCount) {
  if (zone == 0) {
    FailSemanticCapture("ocean neighbor contains a null zone");
  }
  const int ordinal = static_cast<int>(zone->contextOrdinal14);
  if (ordinal < 0 || ordinal >= liveCount || FindMapActionContextByNodeId((short)ordinal) != zone) {
    FailSemanticCapture("ocean neighbor is outside the live ordinal table");
  }
  return ordinal;
}

JSON_Value* CaptureZone(TZone* zone, int liveCount) {
  JsonObject object;
  JsonArray primaryNeighbors;
  JsonArray secondaryNeighbors;

  object.Set("display_name", static_cast<LPCSTR>(zone->displayName));
  object.SetOptional("status_code", static_cast<int>(zone->statusCode04));
  const int targetTile = zone->tileOrTerrainId0c;
  if (targetTile < -1 || targetTile >= 0x1950) {
    FailSemanticCapture("ocean target tile is outside the strategic map");
  }
  object.SetOptional("target_tile", targetTile);
  const int seedOwner = static_cast<int>(zone->seedNationId12);
  if (seedOwner < -1 || seedOwner > 0xff) {
    FailSemanticCapture("ocean seed owner is outside the tile-owner range");
  }
  object.SetOptional("seed_owner", seedOwner);
  const int activeTile = static_cast<int>(zone->activeTileIndex20);
  if (activeTile < -1 || activeTile >= 0x1950) {
    FailSemanticCapture("ocean active tile is outside the strategic map");
  }
  object.SetOptional("active_tile", activeTile);

  const int primaryCount = zone->primaryNeighbors.Count();
  if (primaryCount < 0 || primaryCount > liveCount) {
    FailSemanticCapture("ocean primary-neighbor count is outside the live zone range");
  }
  for (int index = 0; index < primaryCount; ++index) {
    primaryNeighbors.Add(RequiredZoneOrdinal(zone->primaryNeighbors.GetAt(index), liveCount));
  }
  object.Set("primary_neighbors", primaryNeighbors.Release());

  const int secondaryCount = zone->secondaryNeighbors.Count();
  if (secondaryCount < 0 || secondaryCount > 0x180) {
    FailSemanticCapture("ocean secondary-neighbor count is outside the province range");
  }
  for (int secondaryIndex = 0; secondaryIndex < secondaryCount; ++secondaryIndex) {
    Province* province = zone->secondaryNeighbors.Data()[secondaryIndex];
    if (province == 0) {
      FailSemanticCapture("ocean secondary-neighbor list contains a null province");
    }
    const int provinceIndex = static_cast<int>(province->GetIndex());
    if (provinceIndex < 0 || provinceIndex >= 0x180 ||
        &g_pGlobalMapState->cityScoreTable[provinceIndex] != province) {
      FailSemanticCapture("ocean secondary neighbor is outside the province table");
    }
    secondaryNeighbors.Add(provinceIndex);
  }
  object.Set("secondary_neighbors", secondaryNeighbors.Release());
  return object.Release();
}

JSON_Value* CaptureOcean() {
  if (g_pActiveMapOrderContext == 0) {
    FailSemanticCapture("ocean manager is unavailable");
  }
  const int liveCount = ValidateLiveZoneContextCount();
  TZone* orderedZones[0x70];
  memset(orderedZones, 0, sizeof(orderedZones));
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    orderedZones[RequiredZoneOrdinal(zone, liveCount)] = zone;
  }

  JsonObject ocean;
  JsonArray zones;
  for (int ordinal = 0; ordinal < liveCount; ++ordinal) {
    TZone* zone = orderedZones[ordinal];
    if (zone == 0) {
      FailSemanticCapture("ocean ordinal table contains a hole");
    }
    JsonObject entry;
    if (zone->IsKindOf(RUNTIME_CLASS(TPortZone)) != 0) {
      TPortZone* port = static_cast<TPortZone*>(zone);
      const int portTile = static_cast<int>(port->portTileIndex48);
      if (portTile < 0 || portTile >= 0x1950) {
        FailSemanticCapture("port-zone tile is outside the strategic map");
      }
      const int formerOwner =
          static_cast<int>(g_pGlobalMapState->terrainStateTable[portTile].formerOwnerNationTag03);
      if (formerOwner < 0 || formerOwner >= kNationSlotCount) {
        FailSemanticCapture("port-zone former owner is outside the nation range");
      }
      JsonObject portObject;
      portObject.Set("zone", CaptureZone(port, liveCount));
      portObject.Set("port_tile", portTile);
      entry.Set("PortZone", portObject.Release());
    } else {
      entry.Set("Zone", CaptureZone(zone, liveCount));
    }
    zones.Add(entry.Release());
  }
  ocean.Set("zones", zones.Release());

  const int routeCount = static_cast<int>(g_pActiveMapOrderContext->routeNodeCount);
  if (routeCount < 0 || (routeCount != 0 && g_pActiveMapOrderContext->routeSegments == 0)) {
    FailSemanticCapture("ocean route table is invalid");
  }
  JsonArray routes;
  for (int routeIndex = 0; routeIndex < routeCount; ++routeIndex) {
    const CRect& route = g_pActiveMapOrderContext->routeSegments[routeIndex];
    JsonObject routeObject;
    routeObject.Set("start_column", static_cast<int>(route.left));
    routeObject.Set("start_row", static_cast<int>(route.top));
    routeObject.Set("end_column", static_cast<int>(route.right));
    routeObject.Set("end_row", static_cast<int>(route.bottom));
    routes.Add(routeObject.Release());
  }
  ocean.Set("routes", routes.Release());
  return ocean.Release();
}

JSON_Value* CapturePendingActions(const signed char* statuses, const short* payloads) {
  JsonObject table;
  for (int index = 0; index < 0x0d; ++index) {
    JsonObject action;
    action.Set("status", static_cast<int>(statuses[index]));
    if (payloads[index] == -1) {
      action.SetNull("payload");
    } else if (payloads[index] < -1) {
      FailSemanticCapture("pending-action payload is below the -1 sentinel");
    } else {
      action.Set("payload", static_cast<int>(payloads[index]));
    }
    table.Set(kPendingActionNames[index], action.Release());
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
  if (threadData == 0) {
    FailSemanticCapture("CRT per-thread random state is unavailable");
  }
  return threadData->randState14;
}

JSON_Value* CaptureTurn(const RuntimeRun& run) {
  ASSERT(g_pSimMgr != 0);
  JsonObject object;
  if (g_pSimMgr->scenarioMapIndexPlusOne > 0) {
    object.Set("scenario_map", static_cast<int>(g_pSimMgr->scenarioMapIndexPlusOne - 1));
  } else {
    object.SetNull("scenario_map");
  }
  object.Set("economic_turn", g_pSimMgr->economicTurn);
  object.Set("diplomacy_year_term_raw", static_cast<int>(g_pSimMgr->field6c));
  object.Set("phase", g_pSimMgr->turnStateCode);
  object.Set("turn_flow_status_flags", g_pSimMgr->turnFlowStatusFlags);
  object.Set("selected_asset_set", static_cast<int>(g_pSimMgr->field6a));
  JsonArray quarterGateByDecade;
  for (int decade = 0; decade < 10; ++decade) {
    quarterGateByDecade.Add(static_cast<int>(g_pSimMgr->phaseStateByDecade[decade]));
  }
  object.Set("quarter_gate_by_decade", quarterGateByDecade.Release());
  object.Set("difficulty", DifficultyName(g_pSimMgr->difficultyLevel));
  object.Set("active_nation", g_pSimMgr->activeNationSlot);
  object.Set("selected_nation", run.SelectedNationSlot());
  object.Set("last_turn_alert_tick", g_lastTurnAlertTick_006a31c0);
  return object.Release();
}

unsigned int ByteSwapNewsDword(unsigned int value) {
  return ((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
         ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24);
}

void ByteSwapNewsEntry(newsEntry* entry) {
  entry->storyId = static_cast<int>(ByteSwapNewsDword(entry->storyId));
  entry->headlineTextOffset = static_cast<int>(ByteSwapNewsDword(entry->headlineTextOffset));
  entry->headlineTextLength = static_cast<int>(ByteSwapNewsDword(entry->headlineTextLength));
  entry->storyTextOffset = static_cast<int>(ByteSwapNewsDword(entry->storyTextOffset));
  entry->storyTextLength = static_cast<int>(ByteSwapNewsDword(entry->storyTextLength));
  entry->reserved14 = static_cast<int>(ByteSwapNewsDword(entry->reserved14));
}

int FindNewsTemplateIndex(const newsEntry& entry, const newsEntry* templates, int count) {
  int match = -1;
  for (int index = 0; index < count; ++index) {
    if (memcmp(&entry, &templates[index], sizeof(entry)) == 0) {
      if (match != -1) {
        FailSemanticCapture("newspaper story matches more than one template row");
      }
      match = index;
    }
  }
  if (match == -1) {
    FailSemanticCapture("newspaper story does not match NEWS.TAB");
  }
  return match;
}

JSON_Value* CaptureNewsArgument(int kind, int value) {
  JsonObject argument;
  switch (kind) {
  case 0:
    argument.Set("kind", "empty");
    break;
  case 1:
    argument.Set("kind", "nation_mask");
    argument.Set("nations", CaptureNewspaperNationMask(value));
    break;
  case 2:
    argument.Set("kind", "nation_list");
    argument.Set("nations", CaptureNewspaperNationMask(value));
    break;
  case 3:
    if (value < 0 || value > 0xffff) {
      FailSemanticCapture("newspaper province argument is outside the unsigned-short range");
    }
    argument.Set("kind", "province");
    argument.Set("province", value);
    break;
  case 4:
    if (value < -0x8000 || value > 0x7fff) {
      FailSemanticCapture("newspaper zone argument is outside the signed-short range");
    }
    argument.Set("kind", "zone");
    argument.Set("ordinal", value);
    break;
  default:
    FailSemanticCapture("newspaper argument has an unknown kind");
  }
  return argument.Release();
}

JSON_Value* CaptureNewsStory(const newsStory& story, const newsEntry* templates,
                             int templateCount) {
  if (story.entry.storyId < -0x8000 || story.entry.storyId > 0x7fff) {
    FailSemanticCapture("newspaper story id is outside the signed-short range");
  }
  if (story.feature38 > 1) {
    FailSemanticCapture("newspaper feature flag is not boolean");
  }
  JsonObject object;
  object.Set("template_index", FindNewsTemplateIndex(story.entry, templates, templateCount));
  object.Set("story_id", story.entry.storyId);
  object.Set("feature", story.feature38 != 0);
  JsonArray arguments;
  for (int argument = 0; argument < 4; ++argument) {
    arguments.Add(CaptureNewsArgument(story.parmKind[argument], story.parmValue[argument]));
  }
  object.Set("arguments", arguments.Release());
  return object.Release();
}

JSON_Value* CaptureNews() {
  const int kNewsTemplateCount = 360;
  JsonObject news;
  JsonArray pages;
  JsonArray lastUsedByNation;

  if (g_pNewsMgr->storyTemplateCount == 0) {
    for (int nation = 0; nation < kMajorNationCount; ++nation) {
      pages.AddNull();
      JsonArray lastUsed;
      for (int index = 0; index < kNewsTemplateCount; ++index) {
        lastUsed.Add(0);
      }
      lastUsedByNation.Add(lastUsed.Release());
    }
    news.Set("pages", pages.Release());
    news.Set("last_used_turn_by_nation_and_template", lastUsedByNation.Release());
    return news.Release();
  }

  if (g_pNewsMgr->storyTemplateCount != kNewsTemplateCount || g_pAssetMgr == 0 ||
      g_pLanguageMgr == 0) {
    FailSemanticCapture("initialized newspaper state does not use the 360-row NEWS.TAB");
  }
  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTabPath());
  if (stream == 0) {
    FailSemanticCapture("NEWS.TAB is unavailable for newspaper capture");
  }
  const int byteCount = g_pAssetMgr->GetResourceStreamSize(stream);
  if (byteCount != kNewsTemplateCount * static_cast<int>(sizeof(newsEntry))) {
    g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
    FailSemanticCapture("NEWS.TAB does not contain exactly 360 rows");
  }
  newsEntry* templates = new newsEntry[kNewsTemplateCount];
  if (templates == 0) {
    g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
    FailSemanticCapture("NEWS.TAB capture allocation failed");
  }
  int bytesRead = byteCount;
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, templates, &bytesRead);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
  if (bytesRead != byteCount) {
    delete[] templates;
    FailSemanticCapture("NEWS.TAB capture read was incomplete");
  }
  for (int index = 0; index < kNewsTemplateCount; ++index) {
    ByteSwapNewsEntry(&templates[index]);
  }

  for (int nation = 0; nation < kMajorNationCount; ++nation) {
    if (g_pNewsMgr->perNationStoryLastUsedTick[nation] == 0) {
      delete[] templates;
      FailSemanticCapture("initialized newspaper state has no last-used history");
    }
    bool hasStory = false;
    for (int column = 0; column < 3; ++column) {
      for (int row = 0; row < 3; ++row) {
        if (g_pNewsMgr->stories[nation][column][row].entry.storyId != 0) {
          hasStory = true;
        }
      }
    }
    if (!hasStory) {
      pages.AddNull();
    } else {
      JsonObject page;
      JsonArray columns;
      for (int column = 0; column < 3; ++column) {
        JsonArray rows;
        for (int row = 0; row < 3; ++row) {
          const newsStory& story = g_pNewsMgr->stories[nation][column][row];
          if (story.entry.storyId == 0) {
            rows.AddNull();
          } else {
            rows.Add(CaptureNewsStory(story, templates, kNewsTemplateCount));
          }
        }
        columns.Add(rows.Release());
      }
      page.Set("stories", columns.Release());
      pages.Add(page.Release());
    }

    JsonArray lastUsed;
    for (int index = 0; index < kNewsTemplateCount; ++index) {
      lastUsed.Add(static_cast<int>(g_pNewsMgr->perNationStoryLastUsedTick[nation][index]));
    }
    lastUsedByNation.Add(lastUsed.Release());
  }
  delete[] templates;
  news.Set("pages", pages.Release());
  news.Set("last_used_turn_by_nation_and_template", lastUsedByNation.Release());
  return news.Release();
}

JSON_Value* CaptureRng() {
  JsonObject object;
  object.Set("crt_rand", RuntimeCrtRandState());
  object.Set("map_generation", g_mapGenLcgState_006a38e8);
  object.Set("zone_status", g_zoneStatusCodePrngSeed_006a5aec);
  return object.Release();
}

JSON_Value* CaptureProvinces();

JSON_Value* CaptureMap() {
  JsonObject object;
  JsonArray tiles;
  object.Set("topology",
             g_pGlobalMapState->hexNeighborWrapHorizontally == 0 ? "wrapping" : "bounded");
  if (g_pGlobalMapState->field8 > 1) {
    FailSemanticCapture("strategic map data-ready flag is not boolean");
  }
  object.Set("map_data_ready", g_pGlobalMapState->field8 != 0);
  if (g_pGlobalMapState->field9 > 1) {
    FailSemanticCapture("strategic map recruit-search flag is not boolean");
  }
  object.Set("recruit_search_active", g_pGlobalMapState->field9 != 0);
  object.Set("city_score_total", g_pGlobalMapState->cityScoreTotal);
  object.Set("scenario_tag", static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText));
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    JsonObject tileObject;
    char tileFlags[192];
    tileObject.Set("terrain", TerrainName(static_cast<int>(tile.GetTerrainKind())));
    if (tile.spriteVariantIndex01 < 0 || tile.spriteVariantIndex01 > 0x3f) {
      FailSemanticCapture("tile sprite variant is outside the resolved range");
    }
    if (tile.riverSpriteCode != 0 && (tile.riverSpriteCode < 0x0b || tile.riverSpriteCode > 0x3a)) {
      FailSemanticCapture("tile river sprite is outside the resolved range");
    }
    if (tile.adjacencyMaskA0a > 0x3f || tile.adjacencyMaskB0b > 0x3f) {
      FailSemanticCapture("tile rendering mask is outside the six-direction range");
    }
    JsonObject rendering;
    rendering.Set("sprite_variant", static_cast<unsigned int>(tile.spriteVariantIndex01));
    if (tile.riverSpriteCode == 0) {
      rendering.SetNull("river_sprite");
    } else {
      rendering.Set("river_sprite", static_cast<unsigned int>(tile.riverSpriteCode));
    }
    rendering.Set("transition_mask", static_cast<unsigned int>(tile.adjacencyMaskA0a));
    rendering.Set("coast_or_secondary_mask", static_cast<unsigned int>(tile.adjacencyMaskB0b));
    tileObject.Set("rendering", rendering.Release());
    ASSERT(tile.ownerNationTag04 >= -1);
    ASSERT(tile.formerOwnerNationTag03 >= -1);
    tileObject.SetOptional("owner_nation", static_cast<int>(tile.ownerNationTag04));
    tileObject.SetOptional("former_owner_nation", static_cast<int>(tile.formerOwnerNationTag03));
    tileObject.Set("owner_border_mask", static_cast<unsigned int>(tile.ownerBorderMask07));
    tileObject.Set("city_border_mask", static_cast<unsigned int>(tile.cityBorderMask08));
    tileObject.Set("water_adjacency_mask", static_cast<unsigned int>(tile.waterAdjacencyMask09));
    tileObject.Set("recruit_search_visited",
                   static_cast<unsigned int>(tile.recruitSearchVisited0e));
    tileObject.Set("per_tile_visited", static_cast<int>(tile.perTileVisitedFlag0f));
    tileObject.Set("marker_slot_index", static_cast<int>(tile.markerSlotIndex10));
    tileObject.Set("tile_action_ordinal", static_cast<int>(tile.tileActionOrdinal1a));
    tileObject.SetOptional("province", static_cast<int>(tile.cityRecordIndex));
    tileObject.Set("development", CaptureTileDevelopment(tile));
    tileObject.Set("edge_resources", CaptureOptionalResourceArray(tile.resourceTypeByEdge, 2));
    SetDirectionalLinks(tileObject, "transport_links",
                        static_cast<unsigned char>(tile.adjacencyBits06));
    SetDirectionalLinks(tileObject, "pending_rail_links", tile.railFlags17);
    if (tile.tileActionState16 == -1) {
      tileObject.SetNull("action");
    } else {
      tileObject.Set("action", static_cast<int>(tile.tileActionState16));
    }
    tileObject.Set("flags", CaptureTileFlags(tile.activeFlags1c, tileFlags));
    ASSERT(tile.regionSubtypeTag05 >= -1);
    tileObject.SetOptional("region", static_cast<int>(tile.regionSubtypeTag05));
    tileObject.Set("gate", static_cast<int>(tile.gateFlag));
    if (tile.secondaryOwnerNationTag18 < -1 ||
        tile.secondaryOwnerNationTag18 >= kMajorNationCount) {
      FailSemanticCapture("tile secondary owner is outside the major-nation range");
    }
    tileObject.SetOptional("secondary_owner_nation",
                           static_cast<int>(tile.secondaryOwnerNationTag18));
    tiles.Add(tileObject.Release());
  }
  object.Set("tiles", tiles.Release());
  object.Set("provinces", CaptureProvinces());
  if (g_pGlobalMapState->pendingRiverMouthTile < -1 ||
      g_pGlobalMapState->pendingRiverMouthTile >= 0x1950) {
    FailSemanticCapture("pending river-mouth tile is outside the strategic map");
  }
  object.SetOptional("pending_river_mouth_tile",
                     static_cast<int>(g_pGlobalMapState->pendingRiverMouthTile));
  return object.Release();
}

JSON_Value* CaptureProvinces() {
  JsonArray provinces;
  for (int provinceIndex = 0; provinceIndex < 0x180; ++provinceIndex) {
    const Province& province = g_pGlobalMapState->cityScoreTable[provinceIndex];
    if (province.ownerNationCode00 < -1 || province.ownerNationCode00 >= kNationSlotCount) {
      FailSemanticCapture("province owner is outside the semantic nation range");
    }
    if (province.formerOwnerNationCode01 < -1 ||
        province.formerOwnerNationCode01 >= kNationSlotCount) {
      FailSemanticCapture("province former owner is outside the semantic nation range");
    }
    const int adjacencyCount = static_cast<int>(province.adjacentRegionCount08);
    if (adjacencyCount < 0 || adjacencyCount > 12) {
      FailSemanticCapture("province adjacency count is outside the retail record range");
    }
    if (province.regionClassA3 < -1 || province.regionClassA3 >= 24) {
      FailSemanticCapture("province region class is outside the semantic range");
    }
    if (province.fortLevel03 < 0 || province.fortLevel03 > 3) {
      FailSemanticCapture("province fort level is outside the semantic range");
    }
    if ((province.exploredByNationMaskA1 & 0x80) != 0) {
      FailSemanticCapture("province exploration mask has an unsupported upper bit set");
    }
    if (province.cityTileIndex04 < -1 || province.cityTileIndex04 >= 0x1950) {
      FailSemanticCapture("province city tile is outside the strategic map");
    }
    const int linkedTileCount = static_cast<int>(province.linkedRegionCount);
    if (linkedTileCount < 0 || linkedTileCount > 0x20) {
      FailSemanticCapture("province linked-tile count is outside the retail record range");
    }
    if (province.secondaryNeighborTileIndex3e < -1 ||
        province.secondaryNeighborTileIndex3e >= 0x1950 ||
        province.primaryNeighborTileIndex40 < -1 || province.primaryNeighborTileIndex40 >= 0x1950) {
      FailSemanticCapture("province neighbor tile is outside the strategic map");
    }
    if (province.navyOrderReachableA0 > 1) {
      FailSemanticCapture("province navy-order reachability flag is not boolean");
    }

    JsonObject object;
    JsonArray adjacency;
    JsonArray adjacencyAnchorTiles;
    JsonArray linkedTiles;
    object.SetOptional("owner", static_cast<int>(province.ownerNationCode00));
    object.SetOptional("former_owner", static_cast<int>(province.formerOwnerNationCode01));
    object.Set("development_stage", static_cast<int>(province.developmentStage));
    for (int neighborIndex = 0; neighborIndex < adjacencyCount; ++neighborIndex) {
      const int adjacentProvince = static_cast<int>(province.adjacentRegionIds0A[neighborIndex]);
      if (adjacentProvince < 0 || adjacentProvince >= 0x180) {
        FailSemanticCapture("active province adjacency ID is outside the province table");
      }
      adjacency.Add(adjacentProvince);
      const int anchorTile = static_cast<int>(province.adjacentRegionAnchorTiles22[neighborIndex]);
      if (anchorTile < 0 || anchorTile >= 0x1950) {
        FailSemanticCapture("active province adjacency anchor is outside the strategic map");
      }
      adjacencyAnchorTiles.Add(anchorTile);
    }
    object.Set("adjacency", adjacency.Release());
    object.Set("adjacency_anchor_tiles", adjacencyAnchorTiles.Release());
    object.SetOptional("region_class", static_cast<int>(province.regionClassA3));
    object.Set("fort_level", static_cast<int>(province.fortLevel03));
    object.SetOptional("city_tile", static_cast<int>(province.cityTileIndex04));
    object.Set("last_turn_tick", static_cast<int>(province.lastTurnTick));
    object.SetOptional("secondary_neighbor_tile",
                       static_cast<int>(province.secondaryNeighborTileIndex3e));
    object.SetOptional("primary_neighbor_tile",
                       static_cast<int>(province.primaryNeighborTileIndex40));
    for (int linkedTileIndex = 0; linkedTileIndex < linkedTileCount; ++linkedTileIndex) {
      const int linkedTile = static_cast<int>(province.linkedTileIndices42[linkedTileIndex]);
      if (linkedTile < 0 || linkedTile >= 0x1950) {
        FailSemanticCapture("active province linked tile is outside the strategic map");
      }
      linkedTiles.Add(linkedTile);
    }
    object.Set("linked_tiles", linkedTiles.Release());
    short resourceDevelopmentByType[kResourceKindCount];
    memset(resourceDevelopmentByType, 0, sizeof(resourceDevelopmentByType));
    for (int resource = kResourceFood; resource < kResourceManufacturedEnd; ++resource) {
      resourceDevelopmentByType[resource] =
          province.resourceDevelopmentCounts82[resource - kResourceFood];
    }
    object.Set("resource_development_by_type", CaptureResourceTable(resourceDevelopmentByType));
    JsonArray exploredByMajors;
    for (int nation = 0; nation < kMajorNationCount; ++nation) {
      exploredByMajors.Add((province.exploredByNationMaskA1 & (1 << nation)) != 0);
    }
    object.Set("explored_by_majors", exploredByMajors.Release());
    object.Set("city_score", province.cityScoreValue);
    object.Set("navy_order_reachable", province.navyOrderReachableA0 != 0);
    object.Set("resource_presence_mask", static_cast<int>(province.resourcePresenceMaskA2));
    object.Set("name", static_cast<LPCSTR>(province.cityNameA4));
    provinces.Add(object.Release());
  }
  return provinces.Release();
}

const char* ForeignMinisterPersonalityName(TForeignMinister* minister) {
  if (minister == 0) {
    FailSemanticCapture("major nation has no foreign minister");
  }
  CRuntimeClass* runtimeClass = minister->GetRuntimeClass();
  if (runtimeClass == RUNTIME_CLASS(TForeignMinister)) {
    return "base";
  }
  if (runtimeClass == RUNTIME_CLASS(TArmsForeignMinister)) {
    return "arms";
  }
  if (runtimeClass == RUNTIME_CLASS(TTraderForeignMinister)) {
    return "trader";
  }
  if (runtimeClass == RUNTIME_CLASS(TTextileForeignMinister)) {
    return "textile";
  }
  if (runtimeClass == RUNTIME_CLASS(TDiplomatForeignMinister)) {
    return "diplomat";
  }
  if (runtimeClass == RUNTIME_CLASS(TBillForeignMinister)) {
    return "bill";
  }
  if (runtimeClass == RUNTIME_CLASS(TTedForeignMinister)) {
    return "ted";
  }
  FailSemanticCapture("major nation has an unknown foreign-minister runtime class");
  return "base";
}

JSON_Value* CaptureDealBook(TGreatPower* nation) {
  JsonObject dealBook;
  for (short commodity = kResourceCotton; commodity < kResourceManufacturedEnd; ++commodity) {
    JsonArray entries;
    const short entryCount = nation->GetTrackedSlotEntryCountLow(commodity);
    if (entryCount < 0) {
      FailSemanticCapture("deal-book entry count is negative");
    }
    for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
      short kind;
      short amount;
      short targetNation;
      int unitPrice;
      nation->ReadTrackedSlotEntryFields(commodity, ordinal, &kind, &amount, &targetNation,
                                         &unitPrice);
      if (kind != kTrackedSlotOfferEntry && kind != kTrackedSlotAcceptEntry) {
        FailSemanticCapture("deal-book entry kind is invalid");
      }
      if (targetNation < 0 || targetNation >= kNationSlotCount) {
        FailSemanticCapture("deal-book nation is outside the semantic range");
      }
      JsonObject entry;
      entry.Set("kind", kind == kTrackedSlotOfferEntry ? "offer" : "accept");
      entry.Set("nation", static_cast<int>(targetNation));
      entry.Set("amount", static_cast<int>(amount));
      entry.Set("unit_price", unitPrice);
      entries.Add(entry.Release());
    }
    dealBook.Set(kResourceNames[commodity], entries.Release());
  }
  return dealBook.Release();
}

JSON_Value* CaptureForeignTradeState(const TForeignMinister* minister) {
  JsonObject state;
  if (minister->interiorBidResource10 == -10) {
    state.SetNull("interior_bid");
  } else {
    if (minister->interiorBidResource10 < kResourceCotton ||
        minister->interiorBidResource10 >= kResourceManufacturedEnd) {
      FailSemanticCapture("foreign-minister interior bid commodity is invalid");
    }
    JsonObject bid;
    bid.Set("commodity", kResourceNames[minister->interiorBidResource10]);
    bid.Set("amount", static_cast<int>(minister->interiorBidAmount12));
    state.Set("interior_bid", bid.Release());
  }
  state.Set("phase_counter", static_cast<int>(minister->diplomacyPhaseCounter18));
  state.Set("refresh_interval", static_cast<int>(minister->tradeBidRefreshInterval1a));
  if (minister->interiorOrderKind1c < 1 || minister->interiorOrderKind1c > 2) {
    FailSemanticCapture("foreign-minister requested ship is outside the recovered range");
  }
  state.Set("requested_ship", ShipTypeName(minister->interiorOrderKind1c));
  state.Set("purchase_priority",
            CaptureTradeCommodityTable(minister->purchasePriorityByResource1e));
  JsonArray preferredResources;
  for (int index = 0; index < 4; ++index) {
    preferredResources.Add(
        CaptureOptionalTradeCommodity(minister->preferredResourceSlots40[index]));
  }
  state.Set("preferred_resources", preferredResources.Release());
  return state.Release();
}

JSON_Value* CapturePendingShip(TGreatPower* nation) {
  if (nation->interiorMinister == 0) {
    FailSemanticCapture("major nation has no interior minister");
  }
  const short pendingShip = nation->interiorMinister->pendingShipType32;
  if (pendingShip == 0) {
    return JsonNullValue();
  }
  if (pendingShip < 1 || pendingShip > 2) {
    FailSemanticCapture("interior-minister pending ship is outside the recovered range");
  }
  return RuntimeJsonString(ShipTypeName(pendingShip));
}

JSON_Value* CapturePendingDevelopmentActions(TCityInteriorMinister* minister) {
  if (minister->list190 == 0) {
    FailSemanticCapture("interior-minister pending development action list is unavailable");
  }
  JsonArray actions;
  const int count = minister->list190->GetSize();
  if (count < 0) {
    FailSemanticCapture("interior-minister pending development action count is negative");
  }
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    const long value = minister->list190->At(ordinal);
    JsonObject action;
    if (value >= 30) {
      action.Set("kind", "industry");
      action.Set("slot", IndustryActionSlotName(static_cast<int>(value - 30)));
    } else {
      action.Set("kind", "land_unit");
      action.Set("unit_type", MilitaryUnitKindName(static_cast<int>(value)));
    }
    actions.Add(action.Release());
  }
  return actions.Release();
}

JSON_Value* CaptureAiCityOrderDemand(TCityInteriorMinister* minister) {
  static const char* const kTrainingNames[2] = {"medium", "high"};
  static const char* const kMilitaryCategoryNames[8] = {
      "light_infantry", "regular_infantry", "heavy_infantry",  "light_cavalry",
      "heavy_cavalry",  "light_artillery",  "heavy_artillery", "demolitionist"};
  static const char* const kShipSlotNames[8] = {
      "merchant_early_primary",      "merchant_early_secondary",  "merchant_advanced_primary",
      "merchant_advanced_secondary", "warship_early_primary",     "warship_early_secondary",
      "warship_advanced_primary",    "warship_advanced_secondary"};

  if (minister->orderMetricTable40[33] != 0 || minister->orderMetricTable40[52] != 0) {
    FailSemanticCapture("interior minister has demand in a fixed null city-order slot");
  }

  JsonObject demand;
  JsonObject training;
  for (int level = 0; level < 2; ++level) {
    training.Set(kTrainingNames[level], static_cast<int>(minister->orderMetricTable40[23 + level]));
  }
  demand.Set("training", training.Release());

  JsonObject military;
  for (int category = 0; category < 8; ++category) {
    military.Set(kMilitaryCategoryNames[category],
                 static_cast<int>(minister->orderMetricTable40[25 + category]));
  }
  demand.Set("military_recruitment", military.Release());

  JsonObject civilian;
  for (int kind = 0; kind < kCivilianUnitKindCount; ++kind) {
    civilian.Set(kCivilianUnitKindNames[kind],
                 static_cast<int>(minister->orderMetricTable40[34 + kind]));
  }
  demand.Set("civilian_recruitment", civilian.Release());

  JsonObject ships;
  for (int slot = 0; slot < 8; ++slot) {
    ships.Set(kShipSlotNames[slot], static_cast<int>(minister->orderMetricTable40[43 + slot]));
  }
  demand.Set("ships", ships.Release());
  demand.Set("transport_capacity", static_cast<int>(minister->orderMetricTable40[51]));

  JsonArray expansions;
  for (int expansionSlot = 0; expansionSlot < 0x10; ++expansionSlot) {
    expansions.Add(
        expansionSlot < 7 ? static_cast<int>(minister->orderMetricTable40[53 + expansionSlot]) : 0);
  }
  demand.Set("expansions", expansions.Release());
  demand.Set("population_growth", static_cast<int>(minister->orderMetricTable40[60]));
  return demand.Release();
}

JSON_Value* CaptureInteriorCivilianState(TGreatPower* nation) {
  if (nation->interiorMinister == 0) {
    FailSemanticCapture("major nation has no interior minister");
  }
  TCityInteriorMinister* minister = nation->interiorMinister;
  JsonObject state;
  const short pendingRecruitment = minister->pendingRecruitmentCommandIndex36;
  if (pendingRecruitment == -1) {
    state.SetNull("pending_recruitment");
  } else {
    state.Set("pending_recruitment", CivilianUnitKindName(pendingRecruitment));
  }
  state.Set("pending_development_actions", CapturePendingDevelopmentActions(minister));
  state.Set("average_development_order_allocation",
            minister->GetAverageDevelopmentOrderAllocation());
  if (minister->field3c < -1 || minister->field3c >= 0x1950) {
    FailSemanticCapture("interior-minister railhead target is outside the strategic map");
  }
  state.SetOptional("railhead_target", static_cast<int>(minister->field3c));
  state.Set("resource_order_metrics", CaptureResourceTable(minister->orderMetricTable40));
  state.Set("city_order_demand", CaptureAiCityOrderDemand(minister));
  state.Set("deferred_labor_shortfall", static_cast<int>(minister->deferredLaborShortfallDA));
  state.Set("production_deficit_by_slot", CaptureShortArray(minister->orderShortTableDC, 0x10));
  state.Set("temporarily_reserved_ship_arms",
            static_cast<int>(minister->temporarilyReservedShipArms186));
  state.Set("railhead_priority_by_resource", CaptureResourceTable(minister->orderTypeTableFC));
  state.Set("exterior_need_by_resource", CaptureResourceTable(minister->orderTypeTable12A));
  state.Set("historical_need_by_resource", CaptureResourceTable(minister->orderTypeTable158));
  state.Set("civilian_order_demand_by_resource",
            CaptureResourceTable(minister->civilianOrderDemandByResourceType194));
  return state.Release();
}

JSON_Value* CaptureAiTradeState(TGreatPower* nation) {
  if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
    return JsonNullValue();
  }
  TAutoGreatPower* automaticNation = static_cast<TAutoGreatPower*>(nation);
  JsonObject state;
  state.Set("temporary_processed_stock",
            CaptureProcessedTradeCommodityTable(automaticNation->actionMetricByQuarter));
  return state.Release();
}

JSON_Value* CaptureMajorNation(TGreatPower* nation) {
  if (nation->defenseMinister == 0) {
    FailSemanticCapture("major nation has no defense minister");
  }
  JsonObject object;
  object.Set("controller",
             nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0 ? "Computer" : "Human");
  object.Set("diplomacy_eligible", nation->diplomacyEligibilityA0 != 0);
  object.Set("ai_zone_targets", CaptureAiZoneTargets(nation));
  object.Set("ai_province_targets", CaptureAiProvinceTargets(nation));
  object.Set("foreign_minister_personality",
             ForeignMinisterPersonalityName(nation->foreignMinister));
  object.Set("foreign_minister_skill_index",
             static_cast<int>(nation->foreignMinister->skillIndexC));
  object.Set("deal_book", CaptureDealBook(nation));
  object.Set("foreign_trade", CaptureForeignTradeState(nation->foreignMinister));
  object.Set("pending_ship", CapturePendingShip(nation));
  object.Set("interior_civilian", CaptureInteriorCivilianState(nation));
  object.Set("ai_trade", CaptureAiTradeState(nation));
  object.Set(
      "development_grant_by_nation",
      CaptureShortArray(nation->foreignMinister->developmentGrantByNation50, kNationSlotCount));
  object.Set("defense_minister_skill_index",
             static_cast<int>(nation->defenseMinister->skillIndexC));
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
  object.Set("scenario_initialized", nation->scenarioInitFlag != 0 ? true : false);
  object.Set("turn_finished", nation->field904 != 0 ? true : false);
  object.Set("pending_actions",
             CapturePendingActions(nation->pendingActionStatus.byAction, nation->field8d6));
  object.Set("diplomacy_budget_base", nation->diplomacyBudgetBase);
  object.Set("escalation_counter", static_cast<int>(nation->escalationCounter));
  object.Set("pending_commitment_cost", nation->pendingCommitmentCost);
  object.Set("pressure_counter", static_cast<int>(nation->pressureCounter));
  object.Set("army_movement_budget", nation->field900);
  object.Set("aid_allocation_total", nation->aidAllocationTotal);
  object.Set("military_expenses", nation->militaryExpenses960);
  object.Set("candidate_nation_flags",
             CaptureUnsignedByteArray(nation->candidateNationFlags, kNationSlotCount));
  object.Set("colony_boycott_flags",
             CaptureUnsignedByteArray(nation->colonyBoycottFlags, kNationSlotCount));
  return object.Release();
}

JSON_Value* CaptureNationCommon(TCountry* country) {
  ASSERT(country != 0);
  if (country->nationSlot < 0 || country->nationSlot >= kNationSlotCount) {
    FailSemanticCapture("country nation slot is outside the semantic range");
  }
  if (country->ownedRegionList == 0) {
    FailSemanticCapture("country has no owned-region list");
  }
  JsonObject common;
  CString displayName;
  country->LoadNationDisplayNameSharedRefFromField8(&displayName);
  common.Set("display_name", static_cast<const char*>(displayName));
  JsonObject status;
  if (country->encodedNationSlot == -1) {
    status.Set("kind", "independent");
  } else if (country->encodedNationSlot >= 100 && country->encodedNationSlot <= 122) {
    status.Set("kind", "protectorate_of");
    status.Set("nation", static_cast<int>(country->encodedNationSlot - 100));
  } else if (country->encodedNationSlot >= 200 && country->encodedNationSlot <= 222) {
    status.Set("kind", "colony_of");
    status.Set("nation", static_cast<int>(country->encodedNationSlot - 200));
  } else {
    FailSemanticCapture("country encoded nation status is outside the semantic ranges");
  }
  common.Set("status", status.Release());

  JsonArray ownedRegions;
  const int ownedRegionCount = country->ownedRegionList->GetSize();
  if (ownedRegionCount < 0 || ownedRegionCount > 0x180) {
    FailSemanticCapture("country owned-region count is outside the province-table range");
  }
  for (int ordinal = 1; ordinal <= ownedRegionCount; ++ordinal) {
    const long province = country->ownedRegionList->At(ordinal);
    if (province < 0 || province >= 0x180) {
      FailSemanticCapture("country owned-region ID is outside the province table");
    }
    ownedRegions.Add(static_cast<int>(province));
  }
  common.Set("owned_regions", ownedRegions.Release());
  common.Set("treasury", country->treasuryValue10);
  common.SetOptional("home_tile", country->homeTileIndex);
  common.Set("trade_policy_by_nation",
             CaptureShortArray(country->needLevelByNation, kNationSlotCount));
  JsonObject unitNameOrdinals;
  for (int kind = 0; kind < kMilitaryUnitKindCount; ++kind) {
    unitNameOrdinals.Set(MilitaryUnitKindName(kind),
                         static_cast<int>(country->unitNameOrdinalByType[kind]));
  }
  common.Set("unit_name_ordinal_by_type", unitNameOrdinals.Release());
  common.Set("unit_name_counter", static_cast<int>(country->unitNameCounter84));
  return common.Release();
}

JSON_Value* CaptureCity(TCity* city);

JSON_Value* CaptureTowns(TGreatPower* nation, bool freshRandomStart) {
  if (nation->townMarkerList == 0) {
    FailSemanticCapture("major nation has no town marker list");
  }
  JsonArray towns;
  const int townCount = nation->townMarkerList->GetCount();
  if (townCount < 0) {
    FailSemanticCapture("major nation has a negative town count");
  }
  for (int townOrdinal = 1; townOrdinal <= townCount; ++townOrdinal) {
    TTown* town = static_cast<TTown*>(nation->townMarkerList->GetEntryByOrdinal(townOrdinal));
    if (town == 0) {
      FailSemanticCapture("major nation town list contains a null entry");
    }
    if (memchr(town->name, '\0', sizeof(town->name)) == 0) {
      FailSemanticCapture("major nation town name is not terminated");
    }
    if (town->tileIndex < 0 || town->tileIndex >= 0x1950) {
      FailSemanticCapture("major nation town tile is outside the strategic map");
    }
    if (town->ownerNation < 0 || town->ownerNation >= kNationSlotCount) {
      FailSemanticCapture("major nation town owner is outside the nation range");
    }
    unsigned char transportLinked = 0;
    unsigned char active = 0;
    memcpy(&transportLinked, &town->transportLinked, 1);
    memcpy(&active, &town->activeFlag, 1);
    if (transportLinked > 1 || active > 1) {
      FailSemanticCapture("major nation town boolean state is not canonical");
    }

    bool resourcesUncalculated = true;
    for (int resource = 0; resource < kResourceKindCount; ++resource) {
      if (town->resourceYieldByType[resource] != 0) {
        resourcesUncalculated = false;
        break;
      }
    }
    // ITown leaves this byte untouched until resource calculation writes it.
    const bool omitAdjacentCity = town->createdTurnTick > 0 && resourcesUncalculated;

    JsonObject object;
    object.Set("name", town->name);
    object.Set("tile", static_cast<int>(town->tileIndex));
    object.Set("created_turn", static_cast<int>(town->createdTurnTick));
    object.Set("owner_nation", static_cast<int>(town->ownerNation));
    object.Set("resource_yield_by_type", CaptureResourceTable(town->resourceYieldByType));
    object.Set("transport_linked", transportLinked != 0);
    object.Set("enabled", static_cast<unsigned int>(static_cast<unsigned char>(town->enabledFlag)));
    if (!omitAdjacentCity) {
      unsigned int hasAdjacentCity = 0;
      if (!freshRandomStart) {
        unsigned char value = 0;
        memcpy(&value, &town->hasAdjacentCity, 1);
        hasAdjacentCity = value;
      }
      object.Set("has_adjacent_city", hasAdjacentCity);
    }
    object.Set("active", active != 0);
    towns.Add(object.Release());
  }
  return towns.Release();
}

JSON_Value* CaptureMajorNationAggregate(int slot, bool freshRandomStart) {
  TCountry* country = g_apTerrainTypeDescriptorTable[slot];
  TGreatPower* nation = g_apNationStates[slot];
  if (country == 0 || nation == 0 || nation->city == 0) {
    FailSemanticCapture("major-nation aggregate is incomplete");
  }
  if (country->nationSlot != slot) {
    FailSemanticCapture("major-nation aggregate is stored in the wrong nation slot");
  }

  JsonObject object;
  object.Set("kind", nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0 ? "auto_great_power"
                                                                           : "great_power");
  object.Set("common", CaptureNationCommon(country));
  object.Set("economy", CaptureMajorNation(nation));
  object.Set("city", CaptureCity(nation->city));
  object.Set("towns", CaptureTowns(nation, freshRandomStart));
  return object.Release();
}

JSON_Value* CaptureNations(bool freshRandomStart) {
  JsonObject nations;
  JsonArray majors;
  JsonArray minors;
  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    majors.Add(CaptureMajorNationAggregate(slot, freshRandomStart));
  }
  for (int minorSlot = kMinorNationFirstSlot; minorSlot < kNationSlotCount; ++minorSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[minorSlot];
    if (country == 0) {
      minors.AddNull();
      continue;
    }
    if (country->nationSlot != minorSlot) {
      FailSemanticCapture("minor-nation aggregate is stored in the wrong nation slot");
    }
    TMinor* minorCountry = static_cast<TMinor*>(country);
    JsonObject minor;
    minor.Set("common", CaptureNationCommon(country));
    JsonArray consortiumMembers;
    for (int index = 0; index < 4; ++index) {
      int member = minorCountry->GetConsortiumMember(index);
      if (member < kMinorNationFirstSlot || member >= kNationSlotCount) {
        FailSemanticCapture("minor consortium member is outside the minor-nation range");
      }
      consortiumMembers.Add(member);
    }
    minor.Set("consortium_members", consortiumMembers.Release());
    JsonObject trade;
    short currentSupply[kResourceKindCount];
    short offers[kResourceKindCount];
    short grantDeltas[kResourceKindCount];
    short independentResourceCounts[kResourceKindCount];
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      currentSupply[resource] = minorCountry->GetCurrentTradeSupply(resource);
      offers[resource] = minorCountry->GetTradeOffer(resource);
      grantDeltas[resource] = minorCountry->GetTradeGrantDelta(resource);
      independentResourceCounts[resource] = minorCountry->GetIndependentResourceCount(resource);
    }
    trade.Set("current_supply", CaptureResourceTable(currentSupply));
    trade.Set("offers", CaptureResourceTable(offers));
    trade.Set("grant_deltas", CaptureResourceTable(grantDeltas));
    JsonObject thresholds;
    thresholds.Set("primary_manufactured_price",
                   static_cast<int>(minorCountry->GetPrimaryManufacturedPriceThreshold()));
    thresholds.Set("secondary_manufactured_price",
                   static_cast<int>(minorCountry->GetSecondaryManufacturedPriceThreshold()));
    thresholds.Set("general_offer_price",
                   static_cast<int>(minorCountry->GetGeneralOfferPriceThreshold()));
    thresholds.Set("random_offer_price",
                   static_cast<int>(minorCountry->GetRandomOfferPriceThreshold()));
    thresholds.Set("coal_offer_price",
                   static_cast<int>(minorCountry->GetCoalOfferPriceThreshold()));
    thresholds.Set("iron_offer_price",
                   static_cast<int>(minorCountry->GetIronOfferPriceThreshold()));
    thresholds.Set("oil_offer_price", static_cast<int>(minorCountry->GetOilOfferPriceThreshold()));
    trade.Set("thresholds", thresholds.Release());
    trade.Set("primary_manufactured_request", CaptureOptionalManufacturedTradeCommodity(
                                                  minorCountry->GetPrimaryManufacturedRequest()));
    trade.Set(
        "secondary_manufactured_request",
        CaptureOptionalManufacturedTradeCommodity(minorCountry->GetSecondaryManufacturedRequest()));
    trade.Set("primary_request_fulfilled",
              static_cast<int>(minorCountry->GetPrimaryManufacturedRequestFulfilledAmount()));
    trade.Set("secondary_request_fulfilled",
              static_cast<int>(minorCountry->GetSecondaryManufacturedRequestFulfilledAmount()));
    trade.Set("independent_resource_counts", CaptureResourceTable(independentResourceCounts));
    minor.Set("trade", trade.Release());
    minors.Add(minor.Release());
  }
  nations.Set("majors", majors.Release());
  nations.Set("minors", minors.Release());
  return nations.Release();
}

const char* StrikePhaseName(short phase) {
  const char* const names[4] = {"Clothing", "Furniture", "Hardware", "Arms"};
  if (phase < 0 || phase >= 4) {
    FailSemanticCapture("population strike phase is outside its semantic range");
  }
  return names[phase];
}

JSON_Value* CapturePopulation(const TPopulationMgr* population) {
  JsonObject object;
  object.Set("count", static_cast<int>(population->populationCount08));
  object.Set("accumulator", static_cast<double>(population->populationCountFloat0c));
  object.Set("strength", static_cast<int>(population->strength));
  object.Set("extra", static_cast<int>(population->extraAt1e));
  object.Set("strike_phase", StrikePhaseName(population->fieldAt20));
  object.Set("baseline_labor", CaptureLaborPool(population->baselineSlots10));
  object.Set("production_labor", CaptureLaborPool(population->productionSlots14));
  object.Set("pending_labor_delta", CaptureLaborPool(population->pendingDeltaSlots18));
  object.Set("predicted_need_by_resource",
             CaptureResourceTable(population->predictedNeedByResource22));
  return object.Release();
}

const char* ProductionConstraintName(short value) {
  switch (value) {
  case kProductionOrderLimitResources:
    return "resources";
  case kProductionOrderLimitWorkforce:
    return "workforce";
  case kProductionOrderLimitCapacity:
    return "capacity";
  case kProductionOrderLimitTreasury:
    return "treasury";
  default:
    FailSemanticCapture("city order has an unknown limiting constraint");
    return "";
  }
}

void RequireExactOrder(TProductionOrder* order, TCity* city, CRuntimeClass* expectedClass,
                       const char* missingDetail, const char* classDetail) {
  if (order == 0) {
    FailSemanticCapture(missingDetail);
  }
  if (order->GetRuntimeClass() != expectedClass) {
    FailSemanticCapture(classDetail);
  }
  if (order->ownerCity != city) {
    FailSemanticCapture("city order points at the wrong owning city");
  }
  if (city->productionSummary1d8 == 0 || order->productionSummary != city->productionSummary1d8) {
    FailSemanticCapture("city order points at the wrong production summary");
  }
  ProductionConstraintName(order->limitingConstraint);
}

JSON_Value* CaptureProductionProgress(const TProductionOrder* order) {
  JsonObject progress;
  progress.Set("quantity", static_cast<int>(order->quantity));
  progress.Set("limiting_constraint", ProductionConstraintName(order->limitingConstraint));
  return progress.Release();
}

JSON_Value* CaptureTrackingByResource(const TProductionOrder* order) {
  return CaptureResourceTable(order->trackingSlots);
}

JSON_Value* CaptureRequestedOrder(const TItemOrder* order) {
  JsonObject state;
  state.Set("progress", CaptureProductionProgress(order));
  state.Set("requested_quantity", static_cast<int>(order->requestedQuantity4c));
  state.Set("tracking_by_resource", CaptureTrackingByResource(order));
  state.Set("accumulated_value", order->accumulatedValue);
  return state.Release();
}

JSON_Value* CaptureShipMaterials(const TProductionOrder* order) {
  JsonObject materials;
  materials.Set("lumber", static_cast<int>(order->trackingSlots[kResourceLumber]));
  materials.Set("fabric", static_cast<int>(order->trackingSlots[kResourceFabric]));
  materials.Set("arms", static_cast<int>(order->trackingSlots[kResourceArms]));
  materials.Set("steel", static_cast<int>(order->trackingSlots[kResourceSteel]));
  materials.Set("coal", static_cast<int>(order->trackingSlots[kResourceCoal]));
  materials.Set("fuel", static_cast<int>(order->trackingSlots[kResourceFuel]));
  return materials.Release();
}

JSON_Value* CaptureItemOrders(TCity* city) {
  static const short kPrimaryInput[9] = {kResourceWool,   kResourceTimber, kResourceTimber,
                                         kResourceIron,   kResourceOil,    kResourceFabric,
                                         kResourceLumber, kResourceSteel,  kResourceSteel};
  static const short kSecondaryInput[9] = {
      kResourceCotton, -1, -1, kResourceCoal, -1, -1, -1, -1, -1};
  static const short kProductionSlot[9] = {0, 4, 4, 2, 6, 1, 5, 3, 3};

  JsonObject items;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    if (resource < kResourceFabric || resource > kResourceArms) {
      items.SetNull(kResourceNames[resource]);
      continue;
    }

    TProductionOrder* base = city->orderSlotsE4[resource];
    CRuntimeClass* expectedClass =
        resource == kResourceFabric ? RUNTIME_CLASS(TOrItemOrder) : RUNTIME_CLASS(TItemOrder);
    RequireExactOrder(base, city, expectedClass, "city item-order slot is unexpectedly empty",
                      "city item-order slot has the wrong runtime class");
    TItemOrder* order = static_cast<TItemOrder*>(base);
    const int specIndex = resource - kResourceFabric;
    if (order->resourceTypeIndex != resource ||
        order->primaryInputResourceId != kPrimaryInput[specIndex] ||
        order->secondaryInputResourceId != kSecondaryInput[specIndex] ||
        order->productionSlot != kProductionSlot[specIndex]) {
      FailSemanticCapture("city item order does not match its fixed retail specification");
    }
    items.Set(kResourceNames[resource], CaptureRequestedOrder(order));
  }
  return items.Release();
}

JSON_Value* CaptureCivilianRecruitmentOrders(TCity* city) {
  static const short kCashCost[kCivilianUnitKindCount] = {1500, 500,  1000, 1000, 2000,
                                                          1000, 1000, 2000, 5000};
  JsonObject orders;
  for (int kind = 0; kind < kCivilianUnitKindCount; ++kind) {
    TUnitOrder* order = city->buildOrderSlots148[9 + kind];
    RequireExactOrder(order, city, RUNTIME_CLASS(TUnitOrder),
                      "city civilian-recruitment slot is unexpectedly empty",
                      "city civilian-recruitment slot has the wrong runtime class");
    if (order->resourceTypeIndex != kind || order->primaryInputResourceId != kResourcePaper ||
        order->primaryInputPerUnit != 2 || order->secondaryInputResourceId != -1 ||
        order->secondaryInputPerUnit != 0 || order->cashCostPerUnit != kCashCost[kind] ||
        order->workforceMode != kHighSkillWorkforceMode || order->specialistMode != 0) {
      FailSemanticCapture(
          "city civilian-recruitment order does not match its fixed retail specification");
    }
    orders.Set(kCivilianUnitKindNames[kind], CaptureProductionProgress(order));
  }
  return orders.Release();
}

JSON_Value* CaptureMilitaryRecruitmentOrders(TCity* city) {
  static const char* const kCategoryNames[8] = {
      "light_infantry", "regular_infantry", "heavy_infantry",  "light_cavalry",
      "heavy_cavalry",  "light_artillery",  "heavy_artillery", "demolitionist"};
  JsonObject orders;
  for (int category = 0; category < 8; ++category) {
    TUnitOrder* order = city->buildOrderSlots148[category];
    RequireExactOrder(order, city, RUNTIME_CLASS(TUnitOrder),
                      "city military-recruitment slot is unexpectedly empty",
                      "city military-recruitment slot has the wrong runtime class");
    if (order->specialistMode != 1 || order->resourceTypeIndex < 0 ||
        order->resourceTypeIndex >= kMilitaryUnitKindCount ||
        g_awTacticalUnitCategoryCodeBySlot[order->resourceTypeIndex] != category + 1) {
      FailSemanticCapture("city military-recruitment order has an invalid category or recipe");
    }
    JsonObject state;
    state.Set("unit_kind", MilitaryUnitKindName(order->resourceTypeIndex));
    state.Set("progress", CaptureProductionProgress(order));
    orders.Set(kCategoryNames[category], state.Release());
  }
  return orders.Release();
}

bool ShipTypeIsValidForOrderSlot(int slot, short shipType) {
  switch (slot) {
  case 0:
    return shipType == 0 || shipType == 1 || shipType == 5;
  case 1:
    return shipType == 0 || shipType == 2 || shipType == 6;
  case 2:
    return shipType == 0 || shipType == 5 || shipType == 10;
  case 3:
    return shipType == 0 || shipType == 6;
  case 4:
    return shipType == 0 || shipType == 3;
  case 5:
    return shipType == 0 || shipType == 4;
  case 6:
    return shipType == 0 || shipType == 7 || shipType == 11 || shipType == 13;
  case 7:
    return shipType == 0 || shipType == 8 || shipType == 9 || shipType == 12;
  default:
    return false;
  }
}

JSON_Value* CaptureShipOrders(TCity* city) {
  static const char* const kSlotNames[8] = {
      "merchant_early_primary",      "merchant_early_secondary",  "merchant_advanced_primary",
      "merchant_advanced_secondary", "warship_early_primary",     "warship_early_secondary",
      "warship_advanced_primary",    "warship_advanced_secondary"};
  JsonObject orders;
  for (int slot = 0; slot < 8; ++slot) {
    TShipOrder* order = city->shipOrderSlots190[slot];
    RequireExactOrder(order, city, RUNTIME_CLASS(TShipOrder),
                      "city ship-order slot is unexpectedly empty",
                      "city ship-order slot has the wrong runtime class");
    const short shipType = order->resourceTypeIndex;
    if (shipType < 0 || shipType >= kIndustryActionSlotCount ||
        !ShipTypeIsValidForOrderSlot(slot, shipType)) {
      FailSemanticCapture("city ship order has an invalid current type for its persistent slot");
    }
    JsonObject state;
    state.Set("ship_type", ShipTypeName(shipType));
    state.Set("progress", CaptureProductionProgress(order));
    state.Set("materials", CaptureShipMaterials(order));
    orders.Set(kSlotNames[slot], state.Release());
  }
  return orders.Release();
}

JSON_Value* CaptureTrainingOrders(TCity* city) {
  static const char* const kLevelNames[2] = {"medium", "high"};
  JsonObject orders;
  for (int level = 0; level < 2; ++level) {
    TProductionOrder* order = city->orderSlotsE4[0x17 + level];
    RequireExactOrder(order, city, RUNTIME_CLASS(TTrainingOrder),
                      "city training-order slot is unexpectedly empty",
                      "city training-order slot has the wrong runtime class");
    if (order->resourceTypeIndex != level + 1) {
      FailSemanticCapture("city training order has the wrong fixed skill-band identity");
    }
    orders.Set(kLevelNames[level], CaptureProductionProgress(order));
  }
  return orders.Release();
}

JSON_Value* CaptureExpansionOrders(TCity* city) {
  JsonArray orders;
  for (int productionSlot = 0; productionSlot < 0x10; ++productionSlot) {
    if (productionSlot >= 7) {
      orders.AddNull();
      continue;
    }
    TProductionOrder* base = city->trailingOrderSlots1b0[2 + productionSlot];
    RequireExactOrder(base, city, RUNTIME_CLASS(TExpansionOrder),
                      "city expansion-order slot is unexpectedly empty",
                      "city expansion-order slot has the wrong runtime class");
    TExpansionOrder* order = static_cast<TExpansionOrder*>(base);
    if (order->resourceTypeIndex != productionSlot ||
        order->primaryInputResourceId != kResourceLumber ||
        order->secondaryInputResourceId != kResourceSteel || order->productionSlot != 0x0e) {
      FailSemanticCapture("city expansion order does not match its fixed retail specification");
    }
    orders.Add(CaptureRequestedOrder(order));
  }
  return orders.Release();
}

JSON_Value* CaptureCityOrders(TCity* city) {
  for (int prefixSlot = 0; prefixSlot < 7; ++prefixSlot) {
    if (city->orderSlotsE4[prefixSlot] != 0) {
      FailSemanticCapture("city fixed null item-prefix slot contains an order");
    }
  }
  for (int gapSlot = 0x11; gapSlot <= 0x16; ++gapSlot) {
    if (city->orderSlotsE4[gapSlot] != 0) {
      FailSemanticCapture("city fixed null item-gap slot contains an order");
    }
  }
  if (city->buildOrderSlots148[8] != 0) {
    FailSemanticCapture("city fixed null recruitment slot contains an order");
  }

  JsonObject orders;
  orders.Set("items", CaptureItemOrders(city));
  orders.Set("civilian_recruitment", CaptureCivilianRecruitmentOrders(city));
  orders.Set("military_recruitment", CaptureMilitaryRecruitmentOrders(city));
  orders.Set("ships", CaptureShipOrders(city));
  orders.Set("training", CaptureTrainingOrders(city));
  orders.Set("expansions", CaptureExpansionOrders(city));

  TProductionOrder* food = city->orderSlotsE4[kResourceFood];
  RequireExactOrder(food, city, RUNTIME_CLASS(TFoodProcessingOrder),
                    "city food-processing slot is unexpectedly empty",
                    "city food-processing slot has the wrong runtime class");
  if (food->resourceTypeIndex != kResourceFood) {
    FailSemanticCapture("city food-processing order has the wrong fixed identity");
  }
  orders.Set("food_processing", CaptureProductionProgress(food));

  TProductionOrder* powerBase = city->trailingOrderSlots1b0[1];
  RequireExactOrder(powerBase, city, RUNTIME_CLASS(TPowerPlantOrder),
                    "city power-plant slot is unexpectedly empty",
                    "city power-plant slot has the wrong runtime class");
  TPowerPlantOrder* power = static_cast<TPowerPlantOrder*>(powerBase);
  if (power->resourceTypeIndex != 0) {
    FailSemanticCapture("city power-plant order has the wrong fixed identity");
  }
  JsonObject powerState;
  powerState.Set("progress", CaptureProductionProgress(power));
  powerState.Set("desired_quantity", static_cast<int>(power->field4c));
  orders.Set("power_plant", powerState.Release());

  TProductionOrder* capacityBase = city->trailingOrderSlots1b0[0];
  RequireExactOrder(capacityBase, city, RUNTIME_CLASS(TCapacityOrder),
                    "city transport-capacity slot is unexpectedly empty",
                    "city transport-capacity slot has the wrong runtime class");
  TCapacityOrder* capacity = static_cast<TCapacityOrder*>(capacityBase);
  if (capacity->resourceTypeIndex != 0x0e || capacity->primaryInputResourceId != kResourceLumber ||
      capacity->secondaryInputResourceId != kResourceSteel || capacity->productionSlot != 0x0e) {
    FailSemanticCapture(
        "city transport-capacity order does not match its fixed retail specification");
  }
  orders.Set("transport_capacity", CaptureRequestedOrder(capacity));

  TProductionOrder* population = city->trailingOrderSlots1b0[9];
  RequireExactOrder(population, city, RUNTIME_CLASS(TPopGrowthOrder),
                    "city population-growth slot is unexpectedly empty",
                    "city population-growth slot has the wrong runtime class");
  if (population->resourceTypeIndex != 1) {
    FailSemanticCapture("city population-growth order has the wrong fixed identity");
  }
  orders.Set("population_growth", CaptureProductionProgress(population));
  return orders.Release();
}

JSON_Value* CaptureCityBuildingWindows(TCity* city) {
  JsonArray windows;
  for (int slot = 0; slot < 0x10; ++slot) {
    if (city->productionFlags21c[slot] == 0) {
      windows.AddNull();
    } else {
      JsonObject position;
      position.Set("left", static_cast<int>(city->production22c[slot]));
      position.Set("top", static_cast<int>(city->production24c[slot]));
      windows.Add(position.Release());
    }
  }
  return windows.Release();
}

JSON_Value* CaptureCityTasks(TCity* city) {
  JsonArray tasks;
  const int count =
      city->trackedOrderList270 != 0 ? city->trackedOrderList270->GetCount() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TCityTask* task =
        static_cast<TCityTask*>(city->trackedOrderList270->GetEntryByOrdinal(ordinal));
    if (task == 0) {
      FailSemanticCapture("city task list contains a null entry");
    }
    JsonObject object;
    object.Set("order_slot", static_cast<int>(task->citySlotIndex));
    object.Set("remaining_attempts", static_cast<int>(task->remainingAttempts));
    object.Set("requested_amount", static_cast<int>(task->requestedAmount));
    object.Set("already_queued", task->alreadyQueuedFlag != 0);
    if (task->serializedTaskKind == 2) {
      TShipBuildingTask* shipTask = static_cast<TShipBuildingTask*>(task);
      JsonObject operation;
      operation.Set("ship_type", ShipTypeName(static_cast<int>(shipTask->requestedShipType14)));
      operation.Set("waiting_for_order_advance", shipTask->waitingForShipOrderAdvance16 != 0);
      JsonObject tagged;
      tagged.Set("ShipConstruction", operation.Release());
      object.Set("operation", tagged.Release());
    } else if (task->serializedTaskKind == 1) {
      object.Set("operation", "ProductionOrder");
    } else {
      FailSemanticCapture("city task has an unsupported serialized kind");
    }
    tasks.Add(object.Release());
  }
  return tasks.Release();
}

JSON_Value* CaptureCityTransportRequests(TCity* city) {
  JsonArray requests;
  const int count = city->eventQueue274 != 0 ? city->eventQueue274->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TCityTransportRequest* request = static_cast<TCityTransportRequest*>(
        city->eventQueue274->GetPtrListEntryByOneBasedIndex(ordinal));
    if (request == 0) {
      FailSemanticCapture("city transport-request list contains a null record");
    }
    if (request->resourceType < 0 || request->resourceType >= kResourceKindCount) {
      FailSemanticCapture("city transport request resource is outside the resource table");
    }
    JsonObject object;
    object.Set("resource", kResourceNames[request->resourceType]);
    object.Set("requested_amount", static_cast<int>(request->requestedAmount));
    requests.Add(object.Release());
  }
  return requests.Release();
}

JSON_Value* CaptureCity(TCity* city) {
  if (city == 0) {
    return JsonNullValue();
  }
  JsonObject object;
  object.Set("orders", CaptureCityOrders(city));
  object.Set("tasks", CaptureCityTasks(city));
  object.Set("transport_requests", CaptureCityTransportRequests(city));
  object.Set("power_plant_upgrade_queued", city->powerPlantUpgradeQueuedFlag04 != 0 ? true : false);
  object.Set("food_substitution_count", static_cast<int>(city->foodSubstitutionCount06));
  object.Set("starvation_population_loss", static_cast<int>(city->starvationPopulationLoss08));
  object.Set("serialized_state", static_cast<int>(city->serializedState0a));
  object.Set("phase_counter", static_cast<int>(city->cityPhaseCounter0c));
  object.Set("military_recruit_count_by_kind",
             CaptureShortArray(city->militaryRecruitCountByKind, kMilitaryUnitKindCount));
  object.Set("civilian_recruit_count_by_kind",
             CaptureShortArray(city->civilianRecruitCountByKind, kCivilianUnitKindCount));
  object.Set("ship_order_count_by_type", CaptureShipTypeCounts(city->orderCountByType5c));
  object.Set("rolling_item_production_score", city->rollingItemProductionScore78);
  object.Set("low_production", city->lowProductionFlag7c != 0 ? true : false);
  object.Set("low_stock", city->lowStockFlag7d != 0 ? true : false);
  object.Set("reserved_by_type", CaptureResourceTable(city->reservedByType7e));
  object.Set("power_available", static_cast<int>(city->powerAvailableB4));
  object.Set("stockpile", CaptureResourceTable(&city->cityStockCottonB6));
  object.Set("production_orders", CaptureShortArray(city->productionOrderTable1dc, 0x10));
  object.Set("production_accum", CaptureShortArray(city->productionAccum1fc, 0x10));
  object.Set("building_windows", CaptureCityBuildingWindows(city));
  object.Set("population_growth_penalty_ticks",
             static_cast<int>(city->populationGrowthPenaltyTicks26c));
  object.Set("unmet_resource_retries", CaptureResourceTable(city->unmetResourceRetryCount278));
  object.Set("consumed_production_input_by_type",
             CaptureResourceTable(city->consumedProductionInputByType2a6));
  object.Set("population", CapturePopulation(city->productionSummary1d8));
  return object.Release();
}

int RuntimeShipIndex(const TShip* target) {
  if (target == 0) {
    return -1;
  }
  int index = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship == target) {
      return index;
    }
    ++index;
  }
  FailSemanticCapture("non-null ship reference is absent from the primary ship list");
  return -1;
}

int RuntimeTaskForceIndex(const TTaskForce* target) {
  if (target == 0) {
    return -1;
  }
  if (g_pNavyOrderManager == 0) {
    FailSemanticCapture("non-null task-force reference has no order manager");
  }
  int index = 0;
  for (TTaskForce* force = g_pNavyOrderManager->orderQueueHead; force != 0;
       force = force->nextForce) {
    if (force == target) {
      return index;
    }
    ++index;
  }
  FailSemanticCapture("non-null task-force reference is absent from the order queue");
  return -1;
}

int RuntimeZoneIndex(const TZone* zone) {
  if (zone == 0) {
    return -1;
  }
  for (TZone* live = g_pMapActionContextListHead; live != 0; live = live->prev18) {
    if (live == zone) {
      const int index = static_cast<int>(live->contextOrdinal14);
      if (index < 0 || index >= g_nMapActionContextCount) {
        FailSemanticCapture("zone reference has an invalid runtime ordinal");
      }
      return index;
    }
  }
  FailSemanticCapture("non-null zone reference is absent from the map-action context list");
  return -1;
}

int RuntimeRequiredZoneIndex(const TZone* zone) {
  const int index = RuntimeZoneIndex(zone);
  if (index < 0) {
    FailSemanticCapture("required zone reference is null");
  }
  return index;
}

JSON_Value* CaptureSelectedShips(TMapOrderChildLinkNode* links) {
  JsonArray ships;
  for (TMapOrderChildLinkNode* link = links; link != 0; link = link->next) {
    JsonObject ship;
    const int shipIndex = RuntimeShipIndex(static_cast<TShip*>(link->payload));
    if (shipIndex < 0) {
      FailSemanticCapture("selected-ship list contains a null ship reference");
    }
    ship.Set("ship", shipIndex);
    ship.Set("selected", link->active != 0 ? true : false);
    ships.Add(ship.Release());
  }
  return ships.Release();
}

JSON_Value* CaptureMilitaryOrder(const TMilitaryUnit* unit) {
  JsonObject order;
  if (unit->unitOrder == kUnitOrderIdle && unit->orderTargetIndex0C < 0) {
    order.Set("kind", "idle");
  } else {
    order.Set("kind", "retail");
    order.Set("code", static_cast<int>(unit->unitOrder));
    ASSERT(unit->orderTargetIndex0C >= -1);
    order.SetOptional("target", static_cast<int>(unit->orderTargetIndex0C));
  }
  order.Set("targets", CaptureOptionalShortArray(unit->orderTargetTiles28, 3));
  order.Set("target_mirrors", CaptureOptionalShortArray(unit->orderTargetTilesMirror2E, 3));
  return order.Release();
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
      ASSERT(unit->tileIndex06 >= -1);
      object.SetOptional("stationed_province", static_cast<int>(unit->tileIndex06));
      object.Set("order", CaptureMilitaryOrder(unit));
      ASSERT(unit->ownerNationSlot18 >= 0 && unit->ownerNationSlot18 < kNationSlotCount);
      object.Set("owner_nation", static_cast<int>(unit->ownerNationSlot18));
      object.Set("roster_id", static_cast<int>(unit->unitRosterId1A));
      object.Set("registered", unit->militaryRegistrationFlag1C != 0 ? true : false);
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

JSON_Value* RuntimeJsonString(const char* value) {
  JSON_Value* json = json_value_init_string(value);
  if (json == 0) {
    abort();
  }
  return json;
}

int RailDirection(short origin, short destination) {
  if (origin < 0 || destination < 0) {
    FailSemanticCapture("rail order references a negative tile");
  }
  for (int direction = 0; direction < kStrategicHexDirectionCount; ++direction) {
    if (TMapMgr::StepHexTileIndexByDirectionWithWrapRules(origin, direction) == destination) {
      return direction;
    }
  }
  FailSemanticCapture("rail order endpoints are not adjacent");
  return 0;
}

JSON_Value* CaptureCivilianWorkOrder(const TCivUnit* unit) {
  if (unit->unitOrder == kUnitOrderIdle || unit->unitOrder == kUnitOrderSleep) {
    return RuntimeJsonString(CivilianWorkOrderName(unit->unitOrder));
  }

  ASSERT(unit->remainingTurns24 > 0);
  JsonObject order;
  JsonObject data;
  if (unit->unitOrder == kUnitOrderRedeploy) {
    ASSERT(unit->orderTargetIndex0C >= 0);
    data.Set("source", static_cast<int>(unit->orderTargetIndex0C));
  } else if (unit->unitOrder == kUnitOrderLayRail) {
    JsonObject segment;
    const int direction = RailDirection(unit->orderTargetIndex0C, unit->tileIndex06);
    segment.Set("origin", static_cast<int>(unit->orderTargetIndex0C));
    segment.Set("destination", static_cast<int>(unit->tileIndex06));
    segment.Set("direction", kSemanticHexDirectionNames[direction]);
    data.Set("segment", segment.Release());
  } else {
    ASSERT(unit->unitOrder == kUnitOrderBuildDepot || unit->unitOrder == kUnitOrderBuildPort ||
           unit->unitOrder == kUnitOrderProspect || unit->unitOrder == kUnitOrderDevelopResource ||
           unit->unitOrder == kUnitOrderBuildFort || unit->unitOrder == kUnitOrderPurchaseLand);
    ASSERT(unit->orderTargetIndex0C >= 0);
    data.Set("source", static_cast<int>(unit->orderTargetIndex0C));
  }
  data.Set("turns", static_cast<int>(unit->remainingTurns24));
  order.Set(CivilianWorkOrderName(unit->unitOrder), data.Release());
  return order.Release();
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
      ASSERT(unit->tileIndex06 >= -1);
      if (unit->tileIndex06 < 0) {
        object.Set("location", "OffMap");
      } else {
        JsonObject location;
        location.Set("OnMap", static_cast<int>(unit->tileIndex06));
        object.Set("location", location.Release());
      }
      object.Set("order", CaptureCivilianWorkOrder(unit));
      ASSERT(unit->ownerNationSlot18 >= 0 && unit->ownerNationSlot18 < kNationSlotCount);
      object.Set("owner_nation", static_cast<int>(unit->ownerNationSlot18));
      object.Set("roster_id", static_cast<int>(unit->unitRosterId1A));
      object.Set("registered", unit->militaryRegistrationFlag1C != 0 ? true : false);
      units.Add(object.Release());
    }
  }
  return units.Release();
}

JSON_Value* CaptureShips() {
  JsonArray ships;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    JsonObject object;
    object.Set("ship_type", ShipTypeName(static_cast<int>(ship->type)));
    object.Set("location", RuntimeRequiredZoneIndex(ship->location));
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

JSON_Value* CaptureAdmirals() {
  JsonArray admirals;
  for (TAdmiral* admiral = g_pNavySecondaryOrderListHead; admiral != 0; admiral = admiral->next) {
    JsonObject object;
    ASSERT(admiral->nationSlot >= 0 && admiral->nationSlot < kNationSlotCount);
    object.Set("nation", static_cast<int>(admiral->nationSlot));
    object.Set("name", static_cast<LPCSTR>(admiral->displayName));
    object.Set("experience", static_cast<int>(admiral->experiencePoints));
    object.SetOptional("ship", RuntimeShipIndex(admiral->assignedShip));
    admirals.Add(object.Release());
  }
  return admirals.Release();
}

JSON_Value* CaptureTaskForceTarget(const TTaskForce* force) {
  JsonObject object;
  if (force->target == 0) {
    object.Set("kind", "none");
    return object.Release();
  }
  if (force->shipOrders == 5) {
    const int province = static_cast<Province*>(force->target)->GetIndex();
    if (province < 0 || province >= 0x180) {
      FailSemanticCapture("task-force province target is outside the province table");
    }
    object.Set("kind", "province");
    object.Set("target", province);
  } else {
    const int zone = RuntimeRequiredZoneIndex(static_cast<TZone*>(force->target));
    object.Set("kind", "zone");
    object.Set("target", zone);
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
    object.Set("location", RuntimeRequiredZoneIndex(force->location));
    object.Set("nation", static_cast<int>(force->nation));
    object.Set("ship_counts", CaptureShortArray(force->shipCountsByToolbarSlot, 4));
    unsigned char defeated = 0;
    memcpy(&defeated, &force->defeated, 1);
    object.Set("defeated", defeated != 0);
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
  object.SetOptional("target_zone", RuntimeZoneIndex(mission->missionTargetZone));
  object.SetOptional("resolved_port_zone", RuntimeZoneIndex(mission->resolvedPortZone));
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
  ASSERT(mission->presentLocation14 >= -1);
  object.SetOptional("present_province", static_cast<int>(mission->presentLocation14));
  ASSERT(mission->targetProvince30 >= 0);
  object.Set("target_province", static_cast<int>(mission->targetProvince30));
  ASSERT(mission->amassingProvince32 >= -1);
  object.SetOptional("amassing_province", static_cast<int>(mission->amassingProvince32));
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
    TArmyMission* defend = static_cast<TArmyMission*>(mission);
    ASSERT(defend->presentLocation14 >= 0);
    JsonObject object;
    object.Set("kind", "defend_province");
    object.Set("province", static_cast<int>(defend->presentLocation14));
    object.Set("army", CaptureArmyMission(defend));
    return object.Release();
  }
  if (mission->IsKindOf(RUNTIME_CLASS(TBlockadePortMission))) {
    TBlockadePortMission* blockade = static_cast<TBlockadePortMission*>(mission);
    JsonObject object;
    object.Set("kind", "blockade_port");
    object.Set("navy", CaptureNavyMission(blockade));
    const int portZone = RuntimeRequiredZoneIndex(blockade->portZoneContext3c);
    object.Set("port_zone", portZone);
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
  FailSemanticCapture("mission queue contains an unsupported runtime class");
  return 0;
}

JSON_Value* CaptureMissions(bool freshRandomStart) {
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
        FailSemanticCapture("mission queue contains a null entry");
      }
      JsonObject object;
      object.Set("nation", nationSlot);
      object.Set("data", CaptureMissionData(mission));
      if (mission->nationId04 != nationSlot) {
        FailSemanticCapture("mission source nation does not match its owning queue");
      }
      ASSERT(mission->pathMarker06 >= -1 && mission->pathMarker06 < kNationSlotCount);
      object.SetOptional("path_nation", static_cast<int>(mission->pathMarker06));
      object.Set("state", static_cast<unsigned int>(mission->state08));
      object.Set("importance_bits", FloatBits(mission->importanceScore0c));
      // TMission construction leaves flag10 untouched. Hold and ReadFrom make it semantic;
      // before either operation, the byte is allocator residue rather than gameplay state.
      object.Set("held", !freshRandomStart && mission->flag10 != 0);
      object.Set("marker", static_cast<unsigned int>(mission->marker11));
      missions.Add(object.Release());
    }
  }
  return missions.Release();
}

JSON_Value* CaptureDiplomacyNotices(TSortedByRelationshipList* queue) {
  JsonArray notices;
  if (queue != 0 && queue->recordSize14 != 4) {
    FailSemanticCapture("diplomacy notice queue record size is not four bytes");
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    if (record == 0) {
      FailSemanticCapture("diplomacy notice queue contains a null record");
    }
    if (record[1] < 0 || record[1] >= kNationSlotCount) {
      FailSemanticCapture("diplomacy notice source is outside the nation range");
    }
    JsonObject object;
    object.Set("source", static_cast<int>(record[1]));
    object.Set("code", static_cast<int>(record[0]));
    notices.Add(object.Release());
  }
  return notices.Release();
}

JSON_Value* CaptureDiplomacyProposals(TSortedByRelationshipList* queue) {
  JsonArray proposals;
  if (queue != 0 && queue->recordSize14 != 4) {
    FailSemanticCapture("diplomacy proposal queue record size is not four bytes");
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* record = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    if (record == 0) {
      FailSemanticCapture("diplomacy proposal queue contains a null record");
    }
    if (record[1] < 0 || record[1] >= kNationSlotCount) {
      FailSemanticCapture("diplomacy proposal source is outside the nation range");
    }
    JsonObject object;
    object.Set("source", static_cast<int>(record[1]));
    object.Set("policy", DiplomacyPolicyName(record[0]));
    proposals.Add(object.Release());
  }
  return proposals.Release();
}

JSON_Value* CaptureTurnSummary(TSortedByRelationshipList* queue) {
  JsonArray summaries;
  if (queue != 0 && queue->recordSize14 != sizeof(TurnOrderDispatchPacket)) {
    FailSemanticCapture("turn-summary queue record size is not eight bytes");
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TurnOrderDispatchPacket* packet =
        static_cast<TurnOrderDispatchPacket*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    if (packet == 0) {
      FailSemanticCapture("turn-summary queue contains a null record");
    }
    JsonObject object;
    if (packet->orderKind == 3 && packet->payload >= 0 &&
        packet->payload < kMilitaryUnitKindCount) {
      object.Set("kind", "military_recruit");
      object.Set("turn_tick", static_cast<int>(packet->turnTick));
      object.Set("unit_type", MilitaryUnitKindName(packet->payload));
      object.Set("count", static_cast<int>(packet->flags));
    } else {
      object.Set("kind", "retail");
      object.Set("turn_tick", static_cast<int>(packet->turnTick));
      object.Set("order_kind", static_cast<int>(packet->orderKind));
      object.Set("payload", static_cast<int>(packet->payload));
      object.Set("flags", static_cast<int>(packet->flags));
    }
    summaries.Add(object.Release());
  }
  return summaries.Release();
}

JSON_Value* CaptureTurnStartEvents(TSortedList* queue) {
  JsonArray events;
  const int count = queue != 0 ? queue->GetCount() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    TTurnStartEvent* event = static_cast<TTurnStartEvent*>(queue->GetEntryByOrdinal(ordinal));
    if (event == 0) {
      FailSemanticCapture("turn-start event queue contains a null entry");
    }
    CRuntimeClass* runtimeClass = event->GetRuntimeClass();
    JsonObject object;
    if (event->IsKindOf(RUNTIME_CLASS(TLandSaleEvent))) {
      TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
      ASSERT(landSale->nationCode0a >= 0 && landSale->nationCode0a < kNationSlotCount);
      if (landSale->tileIndex08 < 0 || landSale->tileIndex08 >= 0x1950) {
        FailSemanticCapture("land-sale event tile is outside the strategic map");
      }
      JsonObject landSaleObject;
      landSaleObject.Set("tile", static_cast<int>(landSale->tileIndex08));
      landSaleObject.Set("nation", static_cast<int>(landSale->nationCode0a));
      object.Set("kind", "land_sale");
      object.Set("tag", event->eventTag04);
      object.Set("sale", landSaleObject.Release());
    } else {
      object.Set("kind", "tagged");
      object.Set("class", runtimeClass != 0 ? runtimeClass->m_lpszClassName : "unknown");
      object.Set("tag", event->eventTag04);
    }
    events.Add(object.Release());
  }
  return events.Release();
}

JSON_Value* CaptureNationPendingWork(TGreatPower* nation) {
  JsonObject object;
  object.Set("turn_events", CaptureDiplomacyNotices(nation != 0 ? nation->turnEventQueue : 0));
  object.Set("proposals", CaptureDiplomacyProposals(nation != 0 ? nation->proposalQueue : 0));
  object.Set("turn_summary", CaptureTurnSummary(nation != 0 ? nation->turnSummaryQueue : 0));
  object.Set("turn_start_events",
             CaptureTurnStartEvents(nation != 0 ? nation->missionNodeQueue : 0));
  return object.Release();
}

JSON_Value* CapturePendingNewspaperEvents() {
  if (g_pNewsMgr == 0 || g_pNewsMgr->sharedEventRecordQueue == 0) {
    FailSemanticCapture("shared newspaper event queue is unavailable");
  }
  TPtrList* queue = g_pNewsMgr->sharedEventRecordQueue;
  if (queue->recordSize14 != sizeof(InterNationNewsRecord)) {
    FailSemanticCapture("shared newspaper event queue has the wrong record size");
  }

  const int count = queue->GetSize();
  if (count < 0) {
    FailSemanticCapture("shared newspaper event queue has a negative size");
  }
  JsonArray events;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    InterNationNewsRecord* record =
        static_cast<InterNationNewsRecord*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    if (record == 0) {
      FailSemanticCapture("shared newspaper event queue contains a null record");
    }

    JsonObject event;
    if (record->eventKind == kInterNationEventShortage) {
      const int resource = record->payload.relatedNation;
      if (resource < 0 || resource >= kResourceKindCount) {
        FailSemanticCapture("shared newspaper shortage has an invalid resource");
      }
      event.Set("kind", "shortage");
      event.Set("subject", RequiredNewspaperMajorNation(record->payload.subjectNationOrAll));
      event.Set("affected_nations",
                CaptureNewspaperNationMask(record->payload.nationMaskOrStoryCode));
      event.Set("resource", kResourceNames[resource]);
    } else if (record->eventKind == kInterNationEventMiscellaneous) {
      const int audience = record->payload.subjectNationOrAll;
      event.Set("kind", "miscellaneous");
      if (audience == 999) {
        event.SetNull("audience");
      } else {
        event.Set("audience", RequiredNewspaperMajorNation(audience));
      }
      event.Set("story_code", record->payload.nationMaskOrStoryCode);
    } else {
      event.Set("kind", "inter_nation");
      event.Set("event", InterNationNewsKindName(record->eventKind));
      event.Set("subject", RequiredNewspaperMajorNation(record->payload.subjectNationOrAll));
      event.Set("related_nations",
                CaptureNewspaperNationMask(record->payload.nationMaskOrStoryCode));
    }
    events.Add(event.Release());
  }
  return events.Release();
}

JSON_Value* CaptureBattleReports() {
  JsonArray reports;
  if (g_pMapContextActionManager == 0 ||
      g_pMapContextActionManager->mapContextActionRecordList04 == 0) {
    FailSemanticCapture("combat-report state is unavailable");
  }
  TSortedPtrList* list = g_pMapContextActionManager->mapContextActionRecordList04;
  const int combatReportCount = list->GetSize();
  if (combatReportCount < 0 ||
      (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0) != (combatReportCount != 0)) {
    FailSemanticCapture("combat-report count and gate flag disagree");
  }
  const char* const kKindNames[] = {"land_battle", "sea_battle", "merchant_interception",
                                    "preempted_land_battle", "uncontested_takeover"};
  for (int ordinal = 1; ordinal <= combatReportCount; ++ordinal) {
    MapContextActionRecord* record =
        static_cast<MapContextActionRecord*>(list->GetPtrListEntryByOneBasedIndex(ordinal));
    if (record == 0) {
      FailSemanticCapture("combat-report list contains a null record");
    }
    const int kind = record->reportKind04;
    if (kind < 0 || kind > 4) {
      FailSemanticCapture("combat-report kind is outside the recovered domain");
    }
    JsonObject object;
    object.Set("participant_index", static_cast<int>(record->reportParticipantIndex02));
    object.Set("displayed_participant", static_cast<int>(record->displayedParticipantIndex03));
    object.Set("kind", kKindNames[kind]);
    JsonObject location;
    if (kind == kMapContextReportLandBattle || kind == kMapContextReportPreemptedLandBattle ||
        kind == kMapContextReportUncontestedTakeover) {
      location.Set("province", static_cast<int>(reinterpret_cast<unsigned>(record->location08)));
    } else {
      location.Set("zone",
                   RuntimeRequiredZoneIndex(static_cast<TZone*>(record->location08)));
    }
    object.Set("location", location.Release());
    JsonArray sides;
    for (int side = 0; side < 2; ++side) {
      JsonObject sideObject;
      sideObject.Set("nation", static_cast<int>(record->nationIds[side]));
      sideObject.Set("name", record->nameBuffer0c[side].data);
      sideObject.Set("overlay", record->overlayLabel4c[side].data);
      JsonArray children;
      const int childCount = record->childCount24a[side];
      for (int child = 0; child < childCount; ++child) {
        MapOrderBattleSideChildRecord& row = record->sideChildRecords250[side][child];
        JsonObject childObject;
        childObject.Set("resource_type", static_cast<int>(row.resourceType));
        childObject.Set("stock_or_required", static_cast<int>(row.stockOrRequired));
        childObject.Set("name", row.nameBuffer);
        childObject.Set("strength_bucket", static_cast<int>(row.strengthBucket));
        childObject.Set("detail_identity", row.detailIdentity28);
        children.Add(childObject.Release());
      }
      sideObject.Set("children", children.Release());
      sides.Add(sideObject.Release());
    }
    object.Set("sides", sides.Release());
    object.Set("marker_pixel_x", record->markerPixelX258);
    object.Set("marker_pixel_y", record->markerPixelY25c);
    object.Set("placed", record->placedFlag260 != 0);
    object.Set("marker_sprite", static_cast<int>(record->markerSpriteCode262));
    object.Set("list_ordinal", static_cast<int>(record->listOrdinal264));
    reports.Add(object.Release());
  }
  return reports.Release();
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
  if (queue != 0 && queue->recordSize14 != 4) {
    FailSemanticCapture("war-transition queue record size is not four bytes");
  }
  const int count = queue != 0 ? queue->GetSize() : 0;
  for (int ordinal = 1; ordinal <= count; ++ordinal) {
    short* pair = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(ordinal));
    if (pair == 0) {
      FailSemanticCapture("war-transition queue contains a null record");
    }
    if (pair[0] < 0 || pair[0] >= kNationSlotCount || pair[1] < 0 || pair[1] >= kNationSlotCount) {
      FailSemanticCapture("war-transition nation is outside the nation range");
    }
    JsonObject transition;
    transition.Set("first", static_cast<int>(pair[0]));
    transition.Set("second", static_cast<int>(pair[1]));
    transitions.Add(transition.Release());
  }
  object.Set("nations", nations.Release());
  object.Set("newspaper_events", CapturePendingNewspaperEvents());
  object.Set("war_transitions", transitions.Release());
  return object.Release();
}

} // namespace

unsigned int RuntimeCrtRandStateForTests() {
  struct CrtThreadDataPrefix {
    unsigned char prefix00[0x14];
    unsigned int randState14;
  };
  CrtThreadDataPrefix* threadData = static_cast<CrtThreadDataPrefix*>(_getptd());
  if (threadData == 0) {
    return 0;
  }
  return threadData->randState14;
}

static bool BuildRuntimeGameStateWithFreshObjectDefaults(const RuntimeRun& run, JSON_Value** state,
                                                          bool freshRandomStart) {
  if (state == 0 || g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 ||
      g_pGlobalMapState->cityScoreTable == 0 || g_pSimMgr == 0 || g_pTradeMgr == 0 ||
      g_pDiplomacyTurnStateManager == 0 || g_pTechMgr == 0 || g_pNewsMgr == 0) {
    return false;
  }

  JsonObject object;
  object.Set("turn", CaptureTurn(run));
  object.Set("unit_ids", g_pSimMgr->field_64);
  object.Set("map", CaptureMap());
  if (g_pGlobalMapState->field6 < 0 || g_pGlobalMapState->field6 >= 0x1950) {
    FailSemanticCapture("strategic map view origin is outside the map");
  }
  object.Set("map_view_origin", static_cast<int>(g_pGlobalMapState->field6));
  object.Set("ocean", CaptureOcean());
  object.Set("rng", CaptureRng());
  object.Set("market", CaptureMarket());
  object.Set("technology", CaptureTechnology());
  object.Set("diplomacy", CaptureDiplomacy());
  object.Set("nations", CaptureNations(freshRandomStart));
  object.Set("military_units", CaptureMilitaryUnits());
  object.Set("civilian_units", CaptureCivilianUnits());
  object.Set("ships", CaptureShips());
  object.Set("admirals", CaptureAdmirals());
  object.Set("task_forces", CaptureTaskForces());
  object.Set("missions", CaptureMissions(freshRandomStart));
  object.Set("news", CaptureNews());
  object.Set("pending", CapturePending());
  object.Set("battle_reports", CaptureBattleReports());
  *state = object.Release();
  return true;
}

bool BuildRuntimeGameState(const RuntimeRun& run, JSON_Value** state) {
  return BuildRuntimeGameStateWithFreshObjectDefaults(run, state, false);
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

bool CaptureFreshRandomGameState(RuntimeRun& run, const char* name) {
  if (name == 0) {
    return false;
  }
  JSON_Value* state = 0;
  if (!BuildRuntimeGameStateWithFreshObjectDefaults(run, &state, true)) {
    return false;
  }
  run.SetCapture(name, state);
  return true;
}

bool BuildRuntimeEphemeralState(const RuntimeRun& run, JSON_Value** state) {
  if (state == 0 || g_pSimMgr == 0 || g_pDiplomacyTurnStateManager == 0) {
    return false;
  }

  JsonObject object;
  object.Set("turn", CaptureTurn(run));
  object.Set("unit_ids", g_pSimMgr->field_64);
  object.Set("rng", CaptureRng());
  object.Set("news", CaptureNews());
  object.Set("pending", CapturePending());
  SetOptionalMajorNation(object, "last_processed_nation",
                         g_pDiplomacyTurnStateManager->lastProcessedNationSlot);
  *state = object.Release();
  return true;
}

bool CaptureSaveBackedGameState(RuntimeRun& run, const char* name) {
  if (name == 0 || name[0] == '\0' || g_pAssetMgr == 0) {
    return false;
  }

  char saveRelative[260];
  sprintf(saveRelative, "save/rt_native_%s.imp", name);
  if (g_pAssetMgr->SaveMainDocumentToPathAndMarkSaved(CString(saveRelative)) == 0) {
    return false;
  }

  JSON_Value* ephemeral = 0;
  if (!BuildRuntimeEphemeralState(run, &ephemeral)) {
    return false;
  }

  char saveName[64];
  sprintf(saveName, "%s.imp", name);

  JsonObject capture;
  capture.Set("save", saveName);
  capture.Set("ephemeral", ephemeral);
  run.SetCapture(name, capture.Release());
  return run.HasCapture(name);
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
