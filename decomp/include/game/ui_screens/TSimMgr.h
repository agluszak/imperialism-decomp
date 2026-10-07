#pragma once

#include "game/core/CString.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_screens.h"
#include "game/nation_domain_types.h"
#include "game/app/TObject.h"
#include "game/turn_event_codes.h"
#include "game/TTurnInstructionCursor.h"
#include "game/difficulty.h"
#include "game/game_phase.h"
#include "game/session_role.h"

class TStream;

struct GameSetup {
  unsigned char multiplayerGameActive;
  unsigned char pad01;
  short nationControlModes[kMajorNationCount];
  short cityMinisterPolicyIds[7];
  short foreignMinisterPolicyIds[7];
  short defenseMinisterPolicyIds[7];
  unsigned char reloadPoliticalMapState;
  unsigned char pad3b[3];
};

ASSERT_SIZE(GameSetup, 0x3e);

struct DiplomacyNotice {
  short policyOrGrantCode;
  NationSlot nationSlot;
};

ASSERT_SIZE(DiplomacyNotice, 4);

// VTABLE: IMPERIALISM 0x00662a58
class TSimMgr : public TObject {
public:
  TSimMgr();

  // --- TObject overrides (occupy the inherited base slots) ---
  DECLARE_DYNCREATE(TSimMgr)
  ~TSimMgr() override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override; // slot 0x18  0x0057bea0  (scenario setup / rebuild)
  void Free() override;                    // slot 0x1c  0x0057bd20  (manager teardown)

  // --- TSimMgr-introduced virtuals, in exact slot order (byte = index * 4) ---
  virtual void RebuildNationStateSlotsNoOp();
  virtual void CreateGreatPower(int slotIndex, char activate);
  virtual void CreateMinor(int slotIndex);
  virtual void GetSeason(CString* destString);
  virtual void SetGameSetupValues(GameSetup* setup);
  virtual short GetEconomicTurn();
  virtual void AdvanceSeason();
  virtual void StartNextPhase();
  virtual void EnterOptionalPhase(eGamePhaseNewStyle gamePhase);
  virtual void AdvanceGlobalTurnStateMachine();
  virtual bool InLinearPhase();
  virtual void DoCityAndTransport();
  virtual void DoCivilians();
  virtual void DoMilitary();
  virtual void DoTrade();
  virtual bool AllHumansFinished();
  virtual void ResetTurnFlags();
  void MultiSync();
  virtual int PlayerLost();
  virtual void SetFlags(unsigned int flags);
  virtual void NumToCurrency(int value, CString* destString);
  virtual void NumToOrdinal(int value, CString* destString);
  // Copy string-resource group 0x2711 (commodity names) entry `offset` into dest.
  virtual void GetCommodityName(short offset, CString* destString);
  virtual void ReinitializeRandomSeed();
  virtual void GetString(short codeGroup, short offset, CString* destString);
  CString GetCountryName(short slot);
  CString GetCountryNameWithCode(short slot);
  virtual CString DiplomacyNoticeString(const DiplomacyNotice* notice);

  bool TestTurnFlowStatusFlagMask(unsigned int mask);

  // --- non-virtual helpers ---
  int GetNumGPs();
  void ReduceNumGPs();
  int GetNumMinorCountries() const;
  int GetNumCountries(); // Mac oracle; great powers + minor countries
  void DoPerTurnMissionAIStuff(int replanMode);

  NationSlot GetPlayerCountry();
  // ORACLE: the country exists and has not been absorbed. ABI: thiscall; `this` is unused.
  bool ReallyInTheGame(NationSlot nationSlot);
  void EliminateGP(NationSlot nationSlot);
  // Forwards to the player's TGreatPower::SorryYouLose.
  void NotifyActiveNationLost();
  void SetDifficultyLevel(eDifficulty difficulty);
  void ISimMgr();
  void ResetTurnFlowStateAndRandomSeed();
  void UpdatePreferences(bool writeBack);
  void AddHighScore(); // Mac oracle; inserts the player into scores.dat's top ten.
  void CreateSimObjects(bool flag);
  void CreatePlanet(int rebuild, const char* mapName, int wrapHorizontally);
  unsigned char LoadScenario(int scenarioIndex);
  void CreateCountries(int flag);
  void NameCapitals();
  void ProcessScenarioScript();
  // Sets mapArtSet and reloads that picture language pack.
  void SelectMapArtSet(short index);
  void SetPlayerCountry(NationSlot nationSlot);

  void ScSetYear(STurnInstructionCursor* instruction);
  void ScSetFlags(STurnInstructionCursor* instruction);
  void ScSetTechDate(STurnInstructionCursor* instruction);
  void ScSetTransportBar(STurnInstructionCursor* instruction);
  void ScSetTreasury(STurnInstructionCursor* instruction);
  void ScSetTransport(STurnInstructionCursor* instruction);
  void ScClearTransport(STurnInstructionCursor* instruction);
  void ScSetProvince(STurnInstructionCursor* instruction);
  void ScSetRelationship(STurnInstructionCursor* instruction);
  void ScSetProvinceName(STurnInstructionCursor* instruction);
  void ScSetCouncilMeeting(STurnInstructionCursor* instruction);
  void ScSetEmbassy(STurnInstructionCursor* instruction);
  void ScSetWarehouse(STurnInstructionCursor* instruction);
  void ScSetCapacity(STurnInstructionCursor* instruction);
  void ScSetLabor(STurnInstructionCursor* instruction);
  void ScAddArmy(STurnInstructionCursor* instruction);
  void ScAddCivilian(STurnInstructionCursor* instruction);
  void ScAddShip(STurnInstructionCursor* instruction);
  void ScAddRailhead(STurnInstructionCursor* instruction);
  void ScAddPort(STurnInstructionCursor* instruction);
  void ScSetDevLevel(STurnInstructionCursor* instruction);
  void ScAddTech(STurnInstructionCursor* instruction);
  void ScSetPrice(STurnInstructionCursor* instruction);
  void ScSetSubsidy(STurnInstructionCursor* instruction);
  void ScSetTreaty(STurnInstructionCursor* instruction);
  void ScSetSeazoneName(STurnInstructionCursor* instruction);
  void ScSetCountryName(STurnInstructionCursor* instruction);

  eGamePhaseNewStyle turnStateCode;
  eGamePhaseNewStyle mode;
  eGamePhaseNewStyle previousTurnStateCode;
  eGamePhaseNewStyle previousMode;
  unsigned char field14;
  bool countryAvailable[kNationSlotCount];
  short economicTurn;
  NationSlot activeNationSlot;
  int numGreatPowers;
  int numMinorCountries;
  // Transient; not saved.
  unsigned int alertsPendingFlag;
  unsigned int turnFlowStatusFlags;
  // Saved as one byte.
  eDifficulty difficultyLevel;
  // ReinitializeGameFlowAndPostTurnEventCode recreates g_pGameFlowState for any session.
  MultiplayerSessionRole multiplayerSessionRole;
  short preferenceValues[14];
  int lastPersistentUnitId;
  // Names come from string group 0x2715 instead of generated flavor text.
  char useLocalizedNameTables;
  short mapArtSet;
  short finalCouncilYear; // calendar year; 1914 by default
  // Indexed by economicTurn / 40 from 1815; 0 none, 1 council, 2 final council.
  unsigned char councilByDecade[12];
  bool newsEventsSuppressed;
  CString sharedTextSlots[kNationSlotCount];
  unsigned char multiplayerGameActive;
  // Contiguous GameSetup policy rows; no inter-row padding.
  short nationControlModes[kMajorNationCount];
  short cityMinisterPolicyIds[7];
  short foreignMinisterPolicyIds[7];
  short defenseMinisterPolicyIds[7];
  bool reloadPoliticalMapState;
  short scenarioMapIndexPlusOne;
};

ASSERT_SIZE(TSimMgr, 0x118);

int __cdecl TouchSessionActiveNationId(void);

void __cdecl ResetPortZoneGlobalContextCounters(void);

unsigned char __cdecl TryGetFileMetadataForPath(CString* path);
void __cdecl DeleteFileWithErrorReporting(CString* path);

void ReinitializeGameFlowAndPostTurnEventCode(TurnEventId eventCode);

void __stdcall LoadProfileStringAndAssignSharedRef(CString* outString, LPCTSTR key,
                                                   LPCTSTR defaultValue);
