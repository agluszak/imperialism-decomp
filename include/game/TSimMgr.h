#pragma once

#include "game/CString.h"
#include "game/TObject.h"

class TStream;

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
  virtual void ApplyScenarioVariantSeedForNationSetup(CString* destString);    // 0x34  0x0057d830
  // 0x38 — copies the scenario nation-setup buffer into this manager's flow state.
  // (Ghidra mislabelled this "RegisterHotKeyDialogState"; the real call site in TViewMgr
  // passes the assembled setup buffer.)
  virtual void CopyScenarioNationSetupIntoFlowState(void* setupBuffer); // 0x38  0x0057d8d0
  virtual short GetTurnTickSlot3C();                                    // 0x3c  0x0057d8b0
  virtual void IncrementQuarterGateTick2C();                            // 0x40  0x0057d950
  // 0x44 — posts command 100 to the main window so the turn-flow UI re-evaluates. This is the
  // single slot behind both the old "CallSlot44" (TDiplomacyMgr) and "PostTurnFlowUiRefresh"
  // (TGameWindow) names.
  virtual void PostMainWindowCommand100ForTurnFlow();                         // 0x44  0x0057d970
  virtual void SetGlobalTurnStateCodeIfAllowed(int turnStateCode);            // 0x48  0x0057d990
  virtual void AdvanceGlobalTurnStateMachine();                               // 0x4c  0x0057da70
  virtual int IsTurnFlowPhaseOutsideRange4To5();                              // 0x50  0x0057f110
  virtual void RefreshEligibleNationTurnPhaseHandlers();                      // 0x54  0x0057f140
  virtual void DispatchEligibleNationTurnCallback158();                       // 0x58  0x0057f200
  virtual void RefreshMapSystemsAndPrepareOrderExecution();                   // 0x5c  0x0057f280
  virtual void DispatchTurnEvent2134AndRefreshNationPanels();                 // 0x60  0x0057f3c0
  virtual int AreAllActiveNationsReady();                                     // 0x64  0x0057f4f0
  virtual void ClearActiveNationReadyFlags();                                 // 0x68  0x0057f530
  virtual int ReturnZeroSlot6c();                                             // 0x6c  0x0057f490
  virtual void MergeTurnFlowStatusFlags(unsigned int flags);                  // 0x70  0x0057f4b0
  virtual void FormatIntegerString(int value, CString* destString);           // 0x74  0x0057f5b0
  virtual void FormatOrdinalString(int value, CString* destString);           // 0x78  0x0057f8f0
  virtual void TriggerScenarioVariantFormatSlot7c();                          // 0x7c  0x0057fe90
  virtual void ReseedThreadLocalRandom();                                     // 0x80  0x0057fec0
  virtual void GetString(short codeGroup, short offset, CString* destString); // 0x84 0x00580760
  // Copy the per-slot shared credential/name text (sharedTextSlots[slot]) into out and
  // return out. 0x00581b20.
  CString* LoadNormalizedCredentialName(CString* out, short slot);
  // Return a by-value copy of sharedTextSlots[slot] (the copy-constructed hidden-return
  // sibling of LoadNormalizedCredentialName). 0x00581bc0.
  CString AssignSharedStringFromIndexedSlot7C(short slot);
  virtual void FormatDiplomacyNoticeTextByPolicyOrGrantCode(CString* dest,
                                                            short* codes); // 0x88 0x00580790

  char TestTurnFlowStatusFlagMask(unsigned int mask) {
    return (turnFlowStatusFlags & mask) != 0;
  }

  // --- non-virtual helpers ---
  int GetField30();

  // Active great-power slot (this+0x2e). Every original callsite loads ECX from
  // g_pSimMgr (0x6a20f8) — this getter belongs to TSimMgr, not the view
  // managers that many older ports called it on.
  short GetActiveNationId(); // 0x581260
  // 0x581280 -- real __thiscall on the TSimMgr singleton (ret 4; every caller loads
  // g_pSimMgr into ecx); `this` is unused by the body. Slot is eligible when its
  // terrain descriptor exists and (for great powers) isn't a 100..199 profile.
  char IsNationSlotEligibleForEventProcessing(short nationSlot);
  // Store a state code into +0x40 and set the +0x5c short flag to 1 only when the
  // code is exactly zero (codes 1..4 and out-of-range codes clear it). 0x57d870.
  void SetStateCodeAndUpdateZeroOrOutOfRangeFlag(int stateCode);
  void DecrementField30Value();
  void InitializeTurnFlowStateDefaults();
  void InitializeOrLoadEntryArray14AndClampLimits(bool writeBack);
  // 0x57c3b0. Verified against AdvanceGlobalTurnStateMachine's case-3 callsite
  // (0x0057db25): a real __thiscall on TSimMgr (receiver g_pSimMgr), not a
  // free function -- writes into the scenarioSetupRows regions at +0xe8 on `this`.
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
  // 0x581ae0. Sets field6a, then reloads the picture-word-data language pack for
  // that index (EnsurePictWvDataGobLoadedBySlot) and refreshes the strategic map
  // view's cached bitmap 244 (TMacViewMgr::ReloadBitmap244AndRefreshUiCaches on
  // g_pStrategicMapViewSystem).
  void SetSelectedIndex6AAndTriggerRefresh(short index);
  void SetActiveNationSlotAndRefreshCityCapabilityUiHandles(short nationSlot); // 0x5837c0

  // --- turn-instruction stream handlers (dispatched by FourCC through the table at
  //     0x698b50 inside ProcessTurnInstructionStreamAndFinalizePhase; each reads one or
  //     more big-endian tokens from the cursor and mutates this manager / global state) ---
  void
  HandleTurnInstruction_Year_UpdateScenarioYearFieldScaledBy4(void* pInstructionRaw);  // 0x582ed0
  void HandleTurnInstruction_Flag_SetNationFlagAndRefresh(void* pInstructionRaw);      // 0x583400
  void HandleTurnInstruction_Cash_SetNationCash(void* pInstructionRaw);                // 0x583360
  void HandleTurnInstruction_Tran_SetNationTransportStat(void* pInstructionRaw);       // 0x582860
  void HandleTurnInstruction_Tclr_ResetNationRelationBars(void* pInstructionRaw);      // 0x583670
  void HandleTurnInstruction_Prov_ApplyProvinceAssignmentEntry(void* pInstructionRaw); // 0x582f20

  // --- fields (offsets are load-bearing: referenced from many other classes via
  //     g_pSimMgr; do not rename or move) ---
  int turnStateCode;
  int mode;
  int previousTurnStateCode;
  int previousMode;
  unsigned char field14;
  unsigned char field15[0x17];
  short quarterGateTick2c;
  short activeNationSlot;
  int field30;
  int field34;
  unsigned int turnFlowStatusFlags;
  int runtimeSubsystemIndex;
  int redrawEnabled;
  // +0x44 — the multiplayer/session-mode dword: zeroed by the constructor (0x57bae7),
  // compared against 1 and 2 all over TMultiplayerMgr/TMapMgr/TArmyMgr, and tested
  // whole by ReinitializeGameFlowAndPostTurnEventCode (0x5818ad), which tears down and
  // recreates g_pGameFlowState when it is nonzero. Nonzero writer not yet ported.
  int field44;
  // +0x48 — settings-preference slots. Ground truth: InitializeOrLoadEntryArray14AndClampLimits
  // (0x581412 `[this + i*2 + 0x48]`) anchors the array at +0x48, not +0x44 (the earlier
  // +0x44 base — bd 1uj.4's -4 shift — folded field44 into the array and skewed every
  // index by one slot). 14 shorts end at +0x63, so field_64 lands at its literal +0x64
  // with no padding gap. Known slots: [2] clamped 0..100, [3] master volume 0..0xff
  // (TTwoPicSlider writes +0x4e), [8] = the +0x58 turn-gate flag, [10] = the +0x5c
  // pending-event gate (SetStateCodeAndUpdateZeroOrOutOfRangeFlag writes +0x5c).
  short preferenceValues[14];
  int field_64;
  // +0x68 — nonzero: city/nation names come from the localized string table
  // (GetString group 0x2715) instead of the generated flavor-text variants
  // (SetSharedStringFromMappedFlavorTextWithLengthClamp @ 0x5d4410).
  char useLocalizedNameTables68;
  unsigned char pad69;
  short field6a;
  short field6c;
  unsigned char field6e;
  unsigned char phaseFlags[9];
  unsigned char field78;
  unsigned char field79;
  unsigned char gateFlag7a;
  unsigned char pad7b;
  CString sharedTextSlots[0x17];
  unsigned char fieldd8;
  unsigned char padD9;
  // Contiguous 4x7 scenario setup rows at +0xda/+0xe8/+0xf6/+0x104 (constructor
  // scatter-copy evidence; no inter-row padding).
  short scenarioSetupRows0[7];
  short scenarioSetupRows1[7];
  short scenarioSetupRows2[7];
  short scenarioSetupRows3[7];
  unsigned char field112;
  unsigned char pad113;
  // 0x114 — nonzero switches TGreatPower seeding/home-region resolution to the
  // direct-map path (0x004d71b0 / 0x004dfae0 / 0x004df810).
  short stateFlag114;
};

ASSERT_SIZE(TSimMgr, 0x118);

// 0x5d4c10 / 0x5d4c40 — file-metadata probe (CFile::GetStatus) and delete-with-error-box
// (CFile::Remove) helpers from the TSimMgr TU; the save flow in TLoadSavePicture.cpp
// uses them too.
unsigned char __cdecl TryGetFileMetadataForPath(CString* path);
void __cdecl DeleteFileWithErrorReporting(CString* path);

// 0x581870 — the "Done/advance" turn-flow bootstrap primitive (free __cdecl, TSimMgr TU).
// Optionally activates the pending help event (0x5dc), recreates g_pGameFlowState when a
// game flow was active (field44), then either soft-resets the existing TSimMgr for the
// scenario-setup path (eventCode 0x5dd: shared reset prefix, turnStateCode = 3) or
// replaces g_pSimMgr with a fresh TSimMgr and reinitializes its turn-flow defaults.
// Posts eventCode to the main frame (message 0x2420) unless it is 0, and latches the
// bootstrap-complete flag DAT_006a43c0 the turn state machine's case 1 keys off.
void ReinitializeGameFlowAndPostTurnEventCode(int eventCode);

void SaveSettingValueFromPointerByKey(CString* value, const char* key); // 0x5e0260
