#pragma once

#include "game/ui_screens/CString.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_screens.h"
#include "game/nation_domain_types.h"
#include "game/app/TObject.h"
#include "game/turn_event_codes.h"

class TStream;

// Mac CodeWarrior oracle: GameSetup. Windows allocates exactly 0x3e bytes for this
// record before the setup dialog copies the four seven-country rows into it. The
// first row selects local/AI/proxy/remote ownership; the other rows carry the three
// minister policy identifiers consumed by TAutoGreatPower::IAutoGreatPower.
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

// Mac oracle: DiplomacyNotice. Windows consumes this exact two-short payload when
// formatting the turn's diplomacy-notice text.
struct DiplomacyNotice {
  short policyOrGrantCode;
  NationSlot nationSlot;
};

ASSERT_SIZE(DiplomacyNotice, 4);

// TSimMgr — the global turn-flow / simulation manager (historically reached through the
// `g_pSimMgr` singleton @ 0x6a20f8; it also owns the UI string/format helpers,
// which is why callers treat it as a "localization table"). It drives the per-turn state
// machine, rebuilds the nation-state slot tables, and tears the order managers back down.
//
// Parent class recovered from the intact MFC CRuntimeClass chain (m_pBaseClass at +0x10):
//   TSimMgr -> TObject -> CObject
// so TSimMgr is a normal DECLARE_DYNAMIC game object. Its vtable (0x00662a58) has 35 slots
// (0x00..0x88). Slots 0x08/0x0c/0x10/0x20/0x24 (Serialize/AssertValid/Dump/ShallowClone/
// ShallowFree) inherit TObject unchanged and are not redeclared here. The remaining slots are
// declared below in exact vtable order so external virtual call sites resolve to the right
// byte offset.
//
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
  // Mac oracle: GetSeason(CStr255&). Windows computes economicTurn % 4 and looks the
  // localized name up through GetString(10000, seasonIndex, destString).
  virtual void GetSeason(CString* destString);       // 0x34  0x0057d830
  virtual void SetGameSetupValues(GameSetup* setup); // 0x38  0x0057d8d0
  virtual short GetEconomicTurn();                   // 0x3c  0x0057d8b0
  virtual void AdvanceSeason();                      // 0x40  0x0057d950
  // Mac oracle: StartNextPhase(). Windows posts command 100 to the main window so the
  // turn-flow state machine advances asynchronously.
  virtual void StartNextPhase(); // 0x44  0x0057d970
  // Mac oracle: EnterOptionalPhase(eGamePhaseNewStyle). The Windows phase enum is not
  // yet named, so retain its ABI-equivalent int representation.
  virtual void EnterOptionalPhase(int gamePhase); // 0x48  0x0057d990
  virtual void AdvanceGlobalTurnStateMachine();   // 0x4c  0x0057da70
  virtual int InLinearPhase();                    // 0x50  0x0057f110
  virtual void DoCityAndTransport();              // 0x54  0x0057f140, Mac oracle
  virtual void DoCivilians();                     // 0x58  0x0057f200, Mac oracle
  virtual void DoMilitary();                      // 0x5c  0x0057f280, Mac oracle
  virtual void DoTrade();                         // 0x60  0x0057f3c0, Mac oracle
  virtual int AllHumansFinished();                // 0x64  0x0057f4f0
  virtual void ResetTurnFlags();                  // 0x68  0x0057f530
  void PrepareMultiplayerTurnResume();            // 0x0057f570
  virtual int PlayerLost();                       // 0x6c  0x0057f490, Mac oracle
  // Mac oracle: SetFlags(short). Windows reads and merges the full pushed dword.
  virtual void SetFlags(unsigned int flags);                  // 0x70  0x0057f4b0
  virtual void NumToCurrency(int value, CString* destString); // 0x74  0x0057f5b0
  virtual void NumToOrdinal(int value, CString* destString);  // 0x78  0x0057f8f0
  // Copy string-resource group 0x2711 (commodity names) entry `offset` into dest.
  virtual void GetStringPrelude(short offset, CString* destString);           // 0x7c  0x0057fe90
  virtual void ReinitializeRandomSeed();                                      // 0x80  0x0057fec0
  virtual void GetString(short codeGroup, short offset, CString* destString); // 0x84 0x00580760
  // Copy the per-slot shared credential/name text (sharedTextSlots[slot]) into out and
  // return out. 0x00581b20.
  // Byval return (0x581b20): normalizes sharedTextSlots[slot] through
  // TLanguageMgr::NormalizeRuntimeCredentialNameToken.
  CString LoadNormalizedCredentialName(short slot);
  // Return a by-value copy of sharedTextSlots[slot] (the copy-constructed hidden-return
  // sibling of LoadNormalizedCredentialName). 0x00581bc0.
  CString AssignSharedStringFromIndexedSlot7C(short slot);
  virtual CString
  DiplomacyNoticeString(const DiplomacyNotice* notice); // 0x88 0x00580790, Mac oracle

  // 0x57f4d0 — out-of-line in the original build; do not define in-class or MSVC
  // inlines it at every callsite and mismatches all 11 original call instructions.
  unsigned char TestTurnFlowStatusFlagMask(unsigned int mask);

  // --- non-virtual helpers ---
  int GetNumGPs();       // Mac oracle; 0x5811e0
  void ReduceNumGPs();   // Mac oracle; 0x581200
  int GetNumCountries(); // Mac oracle; great powers + minor countries, 0x581240

  // Active great-power slot (this+0x2e). Every original callsite loads ECX from
  // g_pSimMgr (0x6a20f8) — this getter belongs to TSimMgr, not the view
  // managers that many older ports called it on.
  NationSlot GetActiveNationId(); // 0x581260
  // 0x581280 -- real __thiscall on the TSimMgr singleton (ret 4; every caller loads
  // g_pSimMgr into ecx); `this` is unused by the body. Slot is eligible when its
  // terrain descriptor exists and (for great powers) isn't a 100..199 profile.
  char IsNationSlotEligibleForEventProcessing(NationSlot nationSlot);
  // 0x581300 -- removes a nation slot at end of turn: neutralizes the removed nation's
  // percent field on every still-active great power, calls the removed nation's Free(),
  // clears its state/descriptor slots and the per-slot flag byte, decrements the active
  // count, then resets its diplomacy relation matrices via g_pDiplomacyTurnStateManager.
  void RemoveNationSlotAndNotifyPeers(NationSlot nationSlot);
  // Mac symbol oracle: SetDifficultyLevel(eDifficulty). Store the selected difficulty
  // into +0x40 and set the +0x5c short flag only for the zero-valued level; values 1..4
  // and out-of-range values clear it. Windows 0x57d870.
  void SetDifficultyLevel(int difficulty);
  void ISimMgr();
  void InitializeOrLoadEntryArray14AndClampLimits(bool writeBack);
  // 0x581510. Loads the 10-entry {score, name} table from scores.dat (defaulting each
  // slot to {0, this nation's own name} when the file/entry is missing), recomputes the
  // active nation's economy/diplomacy summary, and if its score beats one of the ten
  // entries, shifts the lower entries down and inserts {score, active nation's overlay
  // label} at that position, rewriting the whole table back to scores.dat.
  void UpdatePersistentTopTenNationScores();
  // 0x57c3b0. Verified against AdvanceGlobalTurnStateMachine's case-3 callsite
  // (0x0057db25): a real __thiscall on TSimMgr (receiver g_pSimMgr), not a
  // free function -- writes into the GameSetup policy rows regions at +0xe8 on `this`.
  void RebuildGlobalOrderManagersAndCapabilityState(char flag);
  // 0x57c7c0. Same callsite family (0x0057db32); real __thiscall, 3 stack args
  // (`RET 0xc` confirms the count); param2 is the string literal "Chunk", not a
  // raw address.
  void RebuildMapContextAndGlobalMapState(int param1, const char* param2, int param3);
  // 0x57c9a0: rebuild the active map context + global map state for a numbered
  // scenario ('scn0'..'scz9' session-init tags); returns whether the scenario data loaded.
  unsigned char RecreateActiveMapContextAndInitializeGlobalMapState(int scenarioIndex);
  // 0x57cad0. Verified against 0x0057db53: real __thiscall on `this` (not
  // g_pSimMgr this time), 1 stack arg (`RET 0x4`).
  void RebuildNationStateSlotsAndAvailability(int flag);
  // Mac retail identities for the two state-2 setup branches.
  void NameCapitals();          // 0x581c00
  void ProcessScenarioScript(); // 0x581e60
  // 0x581ae0. Sets field6a, then reloads the picture-word-data language pack for
  // that index (EnsurePictWvDataGobLoadedBySlot) and refreshes the strategic map
  // view's cached bitmap 244 (TMacViewMgr::ReloadBitmap244AndRefreshUiCaches on
  // g_pStrategicMapViewSystem).
  void SetSelectedIndex6AAndTriggerRefresh(short index);
  void SetActiveNationSlotAndRefreshCityCapabilityUiHandles(NationSlot nationSlot); // 0x5837c0

  // --- turn-instruction stream handlers (dispatched by FourCC through the table at
  //     0x698b50 inside ProcessScenarioScript; each reads one or
  //     more big-endian tokens from the cursor and mutates this manager / global state) ---
  void
  HandleTurnInstruction_Year_UpdateScenarioYearFieldScaledBy4(void* pInstructionRaw); // 0x582ed0
  void HandleTurnInstruction_Flag_SetNationFlagAndRefresh(void* pInstructionRaw);     // 0x583400
  void
  HandleTurnInstruction_Tyer_SetCityOrderCapabilityTierValue(void* pInstructionRaw);   // 0x583470
  void HandleTurnInstruction_Tbar_SetNationRelationBarValue(void* pInstructionRaw);    // 0x583510
  void HandleTurnInstruction_Cash_SetNationCash(void* pInstructionRaw);                // 0x583360
  void HandleTurnInstruction_Tran_SetNationTransportStat(void* pInstructionRaw);       // 0x582860
  void HandleTurnInstruction_Tclr_ResetNationRelationBars(void* pInstructionRaw);      // 0x583670
  void HandleTurnInstruction_Prov_ApplyProvinceAssignmentEntry(void* pInstructionRaw); // 0x582f20
  void HandleTurnInstruction_Rela_SetNationRelationValue(void* pInstructionRaw);       // 0x5831d0
  void HandleTurnInstruction_Pnam_AssignProvinceName(void* pInstructionRaw);           // 0x583270
  void HandleTurnInstruction_Coun_SetCountrySlotState(void* pInstructionRaw);          // 0x583700
  void HandleTurnInstruction_Emba_SetEmbassyRelationFlags(void* pInstructionRaw);      // 0x582bf0
  void
  HandleTurnInstruction_Ware_ApplyNationIndexedShortAndRefresh(void* pInstructionRaw);  // 0x5823e0
  void HandleTurnInstruction_Capa_ApplyNationSlotValueWithDelta(void* pInstructionRaw); // 0x5822c0
  void HandleTurnInstruction_Labo_SetNationLaborTierCounts(void* pInstructionRaw);      // 0x582120
  void
  HandleTurnInstruction_Army_DeserializeAndCreateRecruitOrders(void* pInstructionRaw);  // 0x5824c0
  void HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw); // 0x582630
  void
  HandleTurnInstruction_Ship_DeserializeAndCreatePrimaryOrders(void* pInstructionRaw);   // 0x582720
  void HandleTurnInstruction_Rail_ApplyRailPlacementAndCashBonus(void* pInstructionRaw); // 0x5829b0
  void HandleTurnInstruction_Port_ApplyPortPlacementAndCashBonus(void* pInstructionRaw); // 0x582a40
  void HandleTurnInstruction_Deve_ApplyMapDevelopmentEntry(void* pInstructionRaw);       // 0x5828f0
  void
  HandleTurnInstruction_Tech_ApplyTechUnlockAndNotifyNations(void* pInstructionRaw);  // 0x582ad0
  void HandleTurnInstruction_Pric_ApplyDiplomacyPriceEntry(void* pInstructionRaw);    // 0x582b70
  void HandleTurnInstruction_Subs_ApplyNationSubsidyEntry(void* pInstructionRaw);     // 0x582ce0
  void HandleTurnInstruction_Trea_ApplyTreatyAndRelationEntry(void* pInstructionRaw); // 0x582da0
  void
  HandleTurnInstruction_Zone_AssignMapActionContextNameByNodeId(void* pInstructionRaw); // 0x582fa0
  void HandleTurnInstruction_Cnam_AssignCountryName(void* pInstructionRaw);             // 0x583070

  // --- fields (offsets and declaration order are load-bearing) ---
  int turnStateCode;
  int mode;
  int previousTurnStateCode;
  int previousMode;
  unsigned char field14;
  unsigned char field15[0x17];
  short economicTurn;
  NationSlot activeNationSlot;
  int numGreatPowers;
  int numMinorCountries;
  // +0x38 — sign-extended char result of ShowTurnAlertsForActiveNation stored by
  // AdvanceGlobalTurnStateMachine (0x57dcd5). The save stream deliberately skips
  // this transient alert result.
  unsigned int alertsPendingFlag38;
  // +0x3c — session/turn-flow flag word: zeroed by the ctor, OR'd with 0x40 by
  // AdvanceGlobalTurnStateMachine, masked by Merge/TestTurnFlowStatusFlagMask
  // (0x57f4b0/0x57f4d0 both use [ecx+0x3c]), and serialized as a full dword.
  unsigned int turnFlowStatusFlags;
  // +0x40 — difficulty level (Mac eDifficulty; normally 0..4), consumed throughout
  // TCountry/TGreatPower/TDiplomacyMgr balancing logic. Save streams encode it through
  // the integer-byte slot.
  int difficultyLevel;
  // +0x44 — multiplayer role: 0 standalone, 1 host, 2 client. The setup UI writes
  // these values directly, and TMultiplayerMgr/TMapMgr/TArmyMgr branch on the host/client
  // distinction. ReinitializeGameFlowAndPostTurnEventCode recreates g_pGameFlowState
  // whenever the role is nonzero.
  int multiplayerSessionRole;
  // +0x48 — settings-preference slots. Ground truth: InitializeOrLoadEntryArray14AndClampLimits
  // (0x581412 `[this + i*2 + 0x48]`) anchors the array at +0x48, not +0x44 (the earlier
  // +0x44 base — bd 1uj.4's -4 shift — folded multiplayerSessionRole into the array
  // and skewed every index by one slot). 14 shorts end at +0x63, so field_64 lands at
  // its literal +0x64 with no padding gap. Known slots: [2] clamped 0..100, [3] master
  // volume 0..0xff
  // (TTwoPicSlider writes +0x4e), [8] = the +0x58 turn-gate flag, [10] = the +0x5c
  // difficulty-zero gate (SetDifficultyLevel writes +0x5c).
  short preferenceValues[14];
  int field_64;
  // +0x68 — nonzero: city/nation names come from the localized string table
  // (GetString group 0x2715) instead of the generated flavor-text variants
  // (SetSharedStringFromMappedFlavorTextWithLengthClamp @ 0x5d4410).
  char useLocalizedNameTables68;
  unsigned char pad69;
  short field6a;
  short field6c;
  // +0x6e — ten decade-bucket phase-state bytes, indexed by economicTurn / 40.
  unsigned char phaseStateByDecade[10];
  unsigned char field78;
  unsigned char field79;
  unsigned char gateFlag7a;
  unsigned char pad7b;
  CString sharedTextSlots[0x17];
  unsigned char multiplayerGameActive;
  unsigned char padD9;
  // Contiguous GameSetup policy rows; no inter-row padding.
  short nationControlModes[7];
  short cityMinisterPolicyIds[7];
  short foreignMinisterPolicyIds[7];
  short defenseMinisterPolicyIds[7];
  unsigned char reloadPoliticalMapState;
  unsigned char pad113;
  // 0x114 — nonzero switches TGreatPower seeding/home-region resolution to the
  // direct-map path (0x004d71b0 / 0x004dfae0 / 0x004df810).
  short scenarioMapIndexPlusOne;
};

ASSERT_SIZE(TSimMgr, 0x118);

// Free function, NOT a TSimMgr member -- it only looked like one while it sat between the
// class's closing brace and its ASSERT_SIZE. The __cdecl is verified against the assembly,
// not inherited from a Ghidra label: 0x00549240 takes no arguments, loads the g_pNetMgr
// global into ECX and tail-jumps to TNetMgr::GetSessionActiveNationId (0x005e4280).
// Reads the current DirectPlay session id while touching the session runtime state.
int __cdecl TouchSessionActiveNationId(void);

// Also a free function of the TSimMgr TU (0x005621b0): invalidates the zone-graph BFS
// distance cache. Declared here so callers outside this TU stop hand-inlining its two
// global writes -- the original really does CALL it (e.g. 0x00575be0 in
// TGameSetupPicture::DoEvent, through the ILT thunk at 0x004043d1).
void __cdecl ResetPortZoneGlobalContextCounters(void);

// 0x5d4c10 / 0x5d4c40 — file-metadata probe (CFile::GetStatus) and delete-with-error-box
// (CFile::Remove) helpers from the TSimMgr TU; the save flow in TLoadSavePicture.cpp
// uses them too.
unsigned char __cdecl TryGetFileMetadataForPath(CString* path);
void __cdecl DeleteFileWithErrorReporting(CString* path);

// 0x581870 — the "Done/advance" turn-flow bootstrap primitive (free __cdecl, TSimMgr TU).
// Optionally activates the pending help event (0x5dc), recreates g_pGameFlowState when a
// game flow was active (multiplayerSessionRole != 0), then either soft-resets the existing
// TSimMgr for the scenario-setup path (eventCode 0x5dd: shared reset prefix,
// turnStateCode = 3) or
// replaces g_pSimMgr with a fresh TSimMgr and reinitializes its turn-flow defaults.
// Posts eventCode to the main frame (message 0x2420) unless it is 0, and latches the
// bootstrap-complete flag DAT_006a43c0 the turn state machine's case 1 keys off.
void ReinitializeGameFlowAndPostTurnEventCode(TurnEventId eventCode);

void __stdcall LoadProfileStringAndAssignSharedRef(CString* outString, LPCTSTR key,
                                                   LPCTSTR defaultValue); // 0x5e01a0
