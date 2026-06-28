#pragma once

#include "game/CString.h"
#include "game/TObject.h"

class TStream;

// TSimMgr — the global turn-flow / simulation manager (historically reached through the
// `g_pLocalizationTable` singleton @ 0x6a20f8; it also owns the UI string/format helpers,
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
  ~TSimMgr();                                      // slot 0x04  scalar deleting dtor 0x0057bb50
  void WriteTo(TStream* stream) override;          // slot 0x14  0x0057c230
  void ReadFrom(TStream* stream) override; // slot 0x18  0x0057bea0  (scenario setup / rebuild)
  void Free() override;                    // slot 0x1c  0x0057bd20  (manager teardown)

  // --- TSimMgr-introduced virtuals, in exact slot order (byte = index * 4) ---
  virtual void RebuildNationStateSlotsNoOp();                                  // 0x28  0x0057c390
  virtual void RebuildPrimaryNationStateForSlot(int slotIndex, char activate); // 0x2c 0x0057cda0
  virtual void RebuildSecondaryNationStateForSlot(int slotIndex);              // 0x30  0x0057d520
  virtual void ApplyScenarioVariantSeedForNationSetup();                       // 0x34  0x0057d830
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
  virtual void FormatDiplomacyNoticeTextByPolicyOrGrantCode(CString* dest,
                                                            short* codes); // 0x88 0x00580790

  char TestTurnFlowStatusFlagMask(unsigned int mask) {
    return (turnFlowStatusFlags & mask) != 0;
  }

  // --- non-virtual helpers ---
  int GetField30();
  void DecrementField30Value();
  void InitializeTurnFlowStateDefaults();
  void InitializeOrLoadEntryArray14AndClampLimits(bool writeBack);

  // --- fields (offsets are load-bearing: referenced from many other classes via
  //     g_pLocalizationTable; do not rename or move) ---
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
  short preferenceValues[14];
  int field_64;
  unsigned char pad68[2];
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
  short scenarioSetupRows0[7];
  short padE6;
  short scenarioSetupRows1[7];
  short padF4;
  short scenarioSetupRows2[7];
  short pad102;
  short scenarioSetupRows3[7];
  unsigned char field112;
  unsigned char pad113;
  // 0x114 — nonzero switches TGreatPower seeding/home-region resolution to the
  // direct-map path (0x004d71b0 / 0x004dfae0 / 0x004df810).
  short stateFlag114;
};

ASSERT_SIZE(TSimMgr, 0x118);
