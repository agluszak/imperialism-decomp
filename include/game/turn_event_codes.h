#pragma once

// Canonical semantic vocabulary for the turn-event UI domain. VC5 stores this enum as
// an int; retail dispatch/post boundaries use a signed 16-bit value, represented by
// TurnEventCodeStorage and converted explicitly below.
enum TurnEventId {
  kTurnEventRebuildRegisteredWindows = 0x0000,
  kTurnEventAboutBox = 0x03b6,
  kTurnEventCitySiteSelector = 0x03b8,
  kTurnEventNewCityDialog = 0x03b9,
  kTurnEventPlanetSeedDialog = 0x03ba,
  kTurnEventMapEditor = 0x03c0,
  kTurnEventProvinceEditor = 0x03c5,
  kTurnEventVerbFormDialog = 0x03c6,
  kTurnEventDefaultView = 0x03ea,
  kTurnEventCombatReport = 0x0546,
  kTurnEventDiplomacyOffer = 0x0547,
  kTurnEventDetailedBattleReport = 0x0548,
  kTurnEventMainMenu = 0x05dc,
  kTurnEventRandomGameSetup = 0x05dd,
  kTurnEventLoadSave = 0x05de,
  kTurnEventScenarioGameSetup = 0x05df,
  kTurnEventHighScores = 0x05e0,
  kTurnEventNetworkSelect = 0x05e2,
  kTurnEventMultiplayerPickGame = 0x05e3,
  kTurnEventNetworkGameOptions = 0x05e4,
  kTurnEventMultiplayerGameSetup = 0x05e5,
  kTurnEventMultiplayerMessageSend = 0x05e6,
  kTurnEventJoinSelectorMessage = 0x05e7,
  kTurnEventGameScore = 0x05eb,
  kTurnEventSphereWindow = 0x07d1,
  kTurnEventMoveableMainWindow = 0x07d2,
  kTurnEventDiplomacyMap = 0x07d8,
  kTurnEventTradeOverview = 0x07d9,
  kTurnEventIndustryOverview = 0x07da,
  kTurnEventCityProduction = 0x07db,
  kTurnEventStrategicMap = 0x07dd,
  kTurnEventTransport = 0x07de,
  kTurnEventCouncilOfGovernors = 0x07e0,
  kTurnEventCouncilNomination = 0x07e1,
  kTurnEventMinisterMessage = 0x07e4,
  kTurnEventConfirmEndTurn = 0x07e5,
  kTurnEventTechnologyAdvance = 0x0898,
  kTurnEventTechnologyStore = 0x08fc,
  kTurnEventTechnologyHistory = 0x0942,
  kTurnEventHelpMessage = 0x0bb8,
  kTurnEventTerrainHelp = 0x0bbd,
  kTurnEventCivilianInfo = 0x0bc4,
  kTurnEventFriendlyArmyReport = 0x0c1c,
  kTurnEventGarrison = 0x0dac,
  kTurnEventNameUnit = 0x0db4,
  kTurnEventTacticalView = 0x0ed8,
  kTurnEventTacticalBattleResult = 0x0eed,
  // Not a view code. 0x0f0a is the base id of the tactical-map PICT family
  // (Mac: PICT 3850 "Tactical Map 001", TacMaps.rsrc); InitializeBattlefieldView
  // forms picture ids from it (0x5a9eaa ADD EAX,0xf0a). Only the dead vtable slot
  // TViewMgr::HandleTurnEventDialogFactorySlotE8 hands it to the view resolver.
  kTurnEventTacticalMapPictureBase = 0x0f0a,
  kTurnEventTacticalDeployChoice = 0x0f19,
  kTurnEventTacticalStatusRefresh = 0x0f3c,
  kTurnEventUnitHistory = 0x0f3d,
  kTurnEventQueryFloater = 0x101a,
  kTurnEventFlagButton = 0x102c,
  kTurnEventGamePreferences = 0x1036,
  kTurnEventCredits = 0x104f,
  kTurnEventGameStatus = 0x10cc,
  kTurnEventOpeningCinematic = 0x11f8,
  kTurnEventEngineerBuildMenu = 0x1c20,
  // Not a view code. 0x1c52 is a string-list id (Mac: STR# 7250 "Town names",
  // Linger.rsrc/Trade.rsrc); DoPostCreate 0x51bc1a picks a random entry from it
  // via (listId, index). Only the dead vtable slot
  // TViewMgr::HandleTurnEventDialogFactorySlotE4 hands it to the view resolver.
  kTurnEventTownNamesStringList = 0x1c52,
  kTurnEventNewspaperStatus = 0x2103,
  kTurnEventOfferSheet = 0x2134,
  kTurnEventDealBook = 0x2260,
  kTurnEventForeignMinisterRecommendationBook = 0x22e2,
  kTurnEventMerchantMarineBook = 0x22ec,
  kTurnEventMiniDealBook = 0x22f6,
  kTurnEventExportsBook = 0x2300,
  kTurnEventPriceHistoryBook = 0x231e,
  kTurnEventTextileMill = 0x23f0,
  kTurnEventClothingFactory = 0x23f1,
  kTurnEventSteelMill = 0x23f2,
  kTurnEventMetalworks = 0x23f3,
  kTurnEventLumberyard = 0x23f4,
  kTurnEventFurnitureFactory = 0x23f5,
  kTurnEventOilRefinery = 0x23f6,
  kTurnEventShipyard = 0x23f7,
  kTurnEventArmory = 0x23f8,
  kTurnEventSchool = 0x23f9,
  kTurnEventUniversity = 0x23fa,
  kTurnEventPowerPlant = 0x23fb,
  kTurnEventCannery = 0x23fc,
  kTurnEventWarehouse = 0x23fd,
  kTurnEventRailyard = 0x23fe,
  kTurnEventPopulationGrowth = 0x23ff,
  kTurnEventGenericCreator = 0x2404,
  kTurnEventGenericExpander = 0x2405,
  kTurnEventArmyMaker = 0x24f4,
  kTurnEventNavyMaker = 0x24f6,
  kTurnEventTerrainInfo = 0x24f9,
  kTurnEventFriendlyFleetReport = 0x2502,
  kTurnEventEnemyFleetReport = 0x2503,
  kTurnEventMerchantInterceptionReport = 0x2505,
  kTurnEventNavyRoster = 0x2506,
  kTurnEventMinisterReward = 0x2508,
  kTurnEventDefenseMinisterRecommendationBook = 0x258a,
  kTurnEventInteriorMinisterRecommendationBook = 0x25ee,
  kTurnEventTreasuriesBook = 0x25f8,
  kTurnEventCheaterBaseWindow = 0x3a98,
  kTurnEventSpecialDemoQuit = 0x4e20
};

typedef short TurnEventCodeStorage;

inline TurnEventCodeStorage EncodeTurnEventCode(TurnEventId eventCode) {
  return static_cast<TurnEventCodeStorage>(eventCode);
}

inline TurnEventId DecodeTurnEventCode(TurnEventCodeStorage eventCode) {
  return static_cast<TurnEventId>(eventCode);
}
