#pragma once

enum eGamePhaseNewStyle {
  kGamePhaseNone = -1,
  kGamePhaseStartup = 1,
  kGamePhaseStartGame = 2,
  kGamePhaseSetUpMap = 3,
  kGamePhaseShowMap = 4,
  kGamePhaseEndTurn = 5,
  kGamePhaseDiplomacy = 6,
  kGamePhaseTrade = 7,
  kGamePhaseCityAndTransport = 8,
  kGamePhaseCivilians = 9,
  kGamePhaseMilitary = 10,
  kGamePhaseLossCheck = 0x0b,
  kGamePhaseDealBook = 0x0c,
  kGamePhaseBattleReport = 0x0d,
  kGamePhaseCouncil = 0x0e,
  kGamePhaseNews = 0x0f,
  kGamePhaseAdvanceSeason = 0x10,
  kGamePhaseTechnology = 0x11,
  kGamePhaseTurnStart = 0x12,
  kGamePhaseNetworkSync = 0x13,
  kGamePhaseCombat = 0x14,
  kGamePhaseProduction = 0x15,
  kGamePhaseCouncilVictory = 0x16,
  kGamePhaseCouncilDefeat = 0x17,
  kGamePhaseEliminations = 0x19,

  kGamePhaseOptionalDealBook = 100,
  kGamePhaseOptionalBattleReport = 0x65,
  kGamePhaseOptionalNewspaper = 0x66,
  kGamePhaseOptionalTradeOverview = 0x67,
  kGamePhaseOptionalDiplomacyMap = 0x68,
  kGamePhaseOptionalTransport = 0x69,
  kGamePhaseOptionalCityScreen = 0x6a,
  kGamePhaseOptionalGamePreferences = 0x6b,
  kGamePhaseOptionalUnitHistory = 0x6c,
  kGamePhaseOptionalTechStore = 0x6d,
  kGamePhaseOptionalGameStatus = 0x6e,
  kGamePhaseOptionalSaveGame = 0x6f,
  kGamePhaseOptionalLoadGame = 0x70,
  kGamePhaseOptionalCredits = 0x71,
  kGamePhaseOptionalNetworkGameOptions = 0x72
};

// Multiplayer packets carry the phase in a signed 16-bit field.
typedef short GamePhaseStorage;
