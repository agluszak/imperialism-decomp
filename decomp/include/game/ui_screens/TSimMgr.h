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
  unsigned char multiplayerGameActive; // +0x00
  unsigned char pad01;
  short nationControlModes[7];           // +0x02
  short cityMinisterPolicyIds[7];        // +0x10
  short foreignMinisterPolicyIds[7];     // +0x1e
  short defenseMinisterPolicyIds[7];     // +0x2c
  unsigned char reloadPoliticalMapState; // +0x3a
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
  ~TSimMgr() override;                     // slot 0x04  scalar deleting dtor 0x0057bb50
  void WriteTo(TStream* stream) override;  // slot 0x14  0x0057c230
  void ReadFrom(TStream* stream) override; // slot 0x18  0x0057bea0  (scenario setup / rebuild)
  void Free() override;                    // slot 0x1c  0x0057bd20  (manager teardown)

  // --- TSimMgr-introduced virtuals, in exact slot order (byte = index * 4) ---
  virtual void RebuildNationStateSlotsNoOp();                                  // 0x28  0x0057c390
  virtual void RebuildPrimaryNationStateForSlot(int slotIndex, char activate); // 0x2c 0x0057cda0
  virtual void RebuildSecondaryNationStateForSlot(int slotIndex);              // 0x30  0x0057d520
  virtual void GetSeason(CString* destString);                                 // 0x34  0x0057d830
  virtual void SetGameSetupValues(GameSetup* setup);                           // 0x38  0x0057d8d0
  virtual short GetEconomicTurn();                                             // 0x3c  0x0057d8b0
  virtual void AdvanceSeason();                                                // 0x40  0x0057d950
  virtual void StartNextPhase();                                               // 0x44  0x0057d970
  virtual void EnterOptionalPhase(eGamePhaseNewStyle gamePhase); // 0x48  0x0057d990, Mac oracle
  virtual void AdvanceGlobalTurnStateMachine();                  // 0x4c  0x0057da70
  virtual bool InLinearPhase();                                  // 0x50  0x0057f110
  virtual void DoCityAndTransport();                             // 0x54  0x0057f140, Mac oracle
  virtual void DoCivilians();                                    // 0x58  0x0057f200, Mac oracle
  virtual void DoMilitary();                                     // 0x5c  0x0057f280, Mac oracle
  virtual void DoTrade();                                        // 0x60  0x0057f3c0, Mac oracle
  virtual bool AllHumansFinished();                              // 0x64  0x0057f4f0
  virtual void ResetTurnFlags();                                 // 0x68  0x0057f530
  void PrepareMultiplayerTurnResume();                           // 0x0057f570
  virtual int PlayerLost();                                      // 0x6c  0x0057f490, Mac oracle
  virtual void SetFlags(unsigned int flags);                     // 0x70  0x0057f4b0
  virtual void NumToCurrency(int value, CString* destString);    // 0x74  0x0057f5b0
  virtual void NumToOrdinal(int value, CString* destString);     // 0x78  0x0057f8f0
  // Copy string-resource group 0x2711 (commodity names) entry `offset` into dest.
  virtual void GetCommodityName(short offset, CString* destString);           // 0x7c  0x0057fe90
  virtual void ReinitializeRandomSeed();                                      // 0x80  0x0057fec0
  virtual void GetString(short codeGroup, short offset, CString* destString); // 0x84 0x00580760
  CString LoadNormalizedCredentialName(short slot);
  CString GetSharedText(short slot);
  virtual CString
  DiplomacyNoticeString(const DiplomacyNotice* notice); // 0x88 0x00580790, Mac oracle

  bool TestTurnFlowStatusFlagMask(unsigned int mask);

  // --- non-virtual helpers ---
  int GetNumGPs();                  // Mac oracle; 0x5811e0
  void ReduceNumGPs();              // Mac oracle; 0x581200
  int GetNumMinorCountries() const; // 0x581220
  int GetNumCountries();            // Mac oracle; great powers + minor countries, 0x581240
  void DoPerTurnMissionAIStuff(int replanMode); // 0x57d7a0

  NationSlot GetPlayerCountry(); // Mac oracle; 0x581260
  // Mac oracle: the country exists and has not been absorbed. ABI: thiscall; the body
  // ignores `this`. 0x581280.
  bool ReallyInTheGame(NationSlot nationSlot);
  void EliminateGP(NationSlot nationSlot); // Mac oracle; 0x581300
  // Forwards to the player's TGreatPower::SorryYouLose. 0x5813d0.
  void NotifyActiveNationLost();
  void SetDifficultyLevel(eDifficulty difficulty);
  void ISimMgr();
  void ResetTurnFlowStateAndRandomSeed();
  void UpdatePreferences(bool writeBack); // Mac oracle
  void AddHighScore(); // Mac oracle; inserts the player into scores.dat's top ten. 0x581510
  void CreateSimObjects(bool flag);                                          // Mac oracle; 0x57c3b0
  void CreatePlanet(int rebuild, const char* mapName, int wrapHorizontally); // Mac oracle; 0x57c7c0
  unsigned char LoadScenario(int scenarioIndex);                             // Mac oracle; 0x57c9a0
  void CreateCountries(int flag);                                            // Mac oracle; 0x57cad0
  // Mac retail identities for the two state-2 setup branches.
  void NameCapitals();          // 0x581c00
  void ProcessScenarioScript(); // 0x581e60
  // Sets mapArtSet and reloads that picture language pack. 0x581ae0.
  void SelectMapArtSet(short index);
  void SetPlayerCountry(NationSlot nationSlot); // Mac oracle; 0x5837c0

  void ScSetYear(STurnInstructionCursor* instruction);           // 0x582ed0
  void ScSetFlags(STurnInstructionCursor* instruction);          // 0x583400
  void ScSetTechDate(STurnInstructionCursor* instruction);       // 0x583470
  void ScSetTransportBar(STurnInstructionCursor* instruction);   // 0x583510
  void ScSetTreasury(STurnInstructionCursor* instruction);       // 0x583360
  void ScSetTransport(STurnInstructionCursor* instruction);      // 0x582860
  void ScClearTransport(STurnInstructionCursor* instruction);    // 0x583670
  void ScSetProvince(STurnInstructionCursor* instruction);       // 0x582f20
  void ScSetRelationship(STurnInstructionCursor* instruction);   // 0x5831d0
  void ScSetProvinceName(STurnInstructionCursor* instruction);   // 0x583270
  void ScSetCouncilMeeting(STurnInstructionCursor* instruction); // 0x583700
  void ScSetEmbassy(STurnInstructionCursor* instruction);        // 0x582bf0
  void ScSetWarehouse(STurnInstructionCursor* instruction);      // 0x5823e0
  void ScSetCapacity(STurnInstructionCursor* instruction);       // 0x5822c0
  void ScSetLabor(STurnInstructionCursor* instruction);          // 0x582120
  void ScAddArmy(STurnInstructionCursor* instruction);           // 0x5824c0
  void ScAddCivilian(STurnInstructionCursor* instruction);       // 0x582630
  void ScAddShip(STurnInstructionCursor* instruction);           // 0x582720
  void ScAddRailhead(STurnInstructionCursor* instruction);       // 0x5829b0
  void ScAddPort(STurnInstructionCursor* instruction);           // 0x582a40
  void ScSetDevLevel(STurnInstructionCursor* instruction);       // 0x5828f0
  void ScAddTech(STurnInstructionCursor* instruction);           // 0x582ad0
  void ScSetPrice(STurnInstructionCursor* instruction);          // 0x582b70
  void ScSetSubsidy(STurnInstructionCursor* instruction);        // 0x582ce0
  void ScSetTreaty(STurnInstructionCursor* instruction);         // 0x582da0
  void ScSetSeazoneName(STurnInstructionCursor* instruction);    // 0x582fa0
  void ScSetCountryName(STurnInstructionCursor* instruction);    // 0x583070

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
  unsigned char pad69;
  short mapArtSet;
  short finalCouncilYear; // calendar year; 1914 by default
  // Indexed by economicTurn / 40 from 1815; 0 none, 1 council, 2 final council.
  unsigned char councilByDecade[12];
  bool newsEventsSuppressed;
  unsigned char pad7b;
  CString sharedTextSlots[kNationSlotCount];
  unsigned char multiplayerGameActive;
  unsigned char padD9;
  // Contiguous GameSetup policy rows; no inter-row padding.
  short nationControlModes[7];
  short cityMinisterPolicyIds[7];
  short foreignMinisterPolicyIds[7];
  short defenseMinisterPolicyIds[7];
  bool reloadPoliticalMapState;
  unsigned char pad113;
  short scenarioMapIndexPlusOne;
};

ASSERT_SIZE(TSimMgr, 0x118);

int __cdecl TouchSessionActiveNationId(void);

void __cdecl ResetPortZoneGlobalContextCounters(void);

unsigned char __cdecl TryGetFileMetadataForPath(CString* path);
void __cdecl DeleteFileWithErrorReporting(CString* path);

void ReinitializeGameFlowAndPostTurnEventCode(TurnEventId eventCode);

void __stdcall LoadProfileStringAndAssignSharedRef(CString* outString, LPCTSTR key,
                                                   LPCTSTR defaultValue); // 0x5e01a0
