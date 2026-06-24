#include "game/TSimMgr.h"

#include "decomp_types.h"
#include "game/TCountry.h"
#include "game/diplomacy_globals.h"

// Free helper implemented elsewhere; posts UI command 100 to the main window.
undefined4 PostCommand100ToMainWindow(void);

extern "C" {
// TSimMgr's MFC CRuntimeClass descriptor (returned by GetRuntimeClass / vtable slot 0).
// GLOBAL: IMPERIALISM 0x00662960
CRuntimeClass g_pClassDescTSimMgr = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x0057b9c0
CRuntimeClass* TSimMgr::GetRuntimeClass() const {
  return &g_pClassDescTSimMgr;
}

// Partial port: the real constructor also default-constructs the +0x7c CString[0x17]
// array and copies the per-nation setup table (DAT_00698b1a) into the +0xe8 short arrays;
// those remain TODO. Defining the constructor is what forces MSVC to emit TSimMgr's vtable
// so reccmp can verify the slot layout.
// FUNCTION: IMPERIALISM 0x0057b9e0
TSimMgr::TSimMgr() {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4) = 1;
  mode = 1;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xc) = 1;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x10) = 1;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x14) = 0;
  pad2e = static_cast<short>(0xffff);
  quarterGateTick2c = 0;
  field30 = 7;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x34) = 0x10;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0xd8) = 0;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x112) = 0;
  stateFlag114 = 0;
  redrawEnabled = 0;
}

// SYNTHETIC: IMPERIALISM 0x0057bb50
// TSimMgr::`scalar deleting destructor'
TSimMgr::~TSimMgr() {}

// TODO: port teardown of the global map/order-manager singletons and nation-state tables
// (overrides TObject::Free; releases g_pNationInteractionStateManager,
// g_pDiplomacyTurnStateManager, g_pMapContextActionManager, ... via their own vtables).
// FUNCTION: IMPERIALISM 0x0057bd20
void TSimMgr::Free() {}

// TODO: port scenario-state initialization / nation-system rebuild (overrides TObject::ReadFrom).
// FUNCTION: IMPERIALISM 0x0057bea0
void TSimMgr::ReadFrom(TStream*) {}

// TODO: port the field serialization writer (overrides TObject::WriteTo).
// FUNCTION: IMPERIALISM 0x0057c230
void TSimMgr::WriteTo(TStream*) {}

// FUNCTION: IMPERIALISM 0x0057c390
void TSimMgr::RebuildNationStateSlotsNoOp() {}

// TODO: port primary nation-state slot rebuild (allocates TGreatPower / proxy / remote
// variants and rebinds the display/name tables).
// FUNCTION: IMPERIALISM 0x0057cda0
void TSimMgr::RebuildPrimaryNationStateForSlot(int, char) {}

// TODO: port secondary (minor) nation-state slot rebuild.
// FUNCTION: IMPERIALISM 0x0057d520
void TSimMgr::RebuildSecondaryNationStateForSlot(int) {}

// TODO: port scenario-variant RNG seeding for nation setup.
// FUNCTION: IMPERIALISM 0x0057d830
void TSimMgr::ApplyScenarioVariantSeedForNationSetup() {}

// FUNCTION: IMPERIALISM 0x0057d8b0
short TSimMgr::GetTurnTickSlot3C() {
  return quarterGateTick2c;
}

// TODO: port the copy of the scenario nation-setup buffer into flow state (writes the
// per-nation short arrays around +0xe8 and the +0x112 direct-map flag).
// FUNCTION: IMPERIALISM 0x0057d8d0
void TSimMgr::CopyScenarioNationSetupIntoFlowState(void*) {}

// FUNCTION: IMPERIALISM 0x0057d950
void TSimMgr::IncrementQuarterGateTick2C() {
  ++quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x0057d970
void TSimMgr::PostMainWindowCommand100ForTurnFlow() {
  PostCommand100ToMainWindow();
}

// FUNCTION: IMPERIALISM 0x0057d990
void TSimMgr::SetGlobalTurnStateCodeIfAllowed(int turnStateCode) {
  short nationSlot = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x2e);
  bool allowStateChange;
  if (nationSlot == -1) {
    allowStateChange = false;
  } else {
    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
    if (terrainDescriptor == 0) {
      allowStateChange = false;
    } else {
      if (nationSlot < 7) {
        short field0e = *reinterpret_cast<short*>(reinterpret_cast<char*>(terrainDescriptor) + 0xe);
        if (terrainDescriptor == 0 || field0e < 100 || field0e > 199) {
          allowStateChange = false;
        } else {
          allowStateChange = true;
        }
        if (allowStateChange) {
          allowStateChange = false;
          goto check_turn_state_code;
        }
      }
      allowStateChange = true;
    }
  }
check_turn_state_code:
  if (!allowStateChange) {
    switch (turnStateCode) {
    case 100:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6d:
      return;
    }
  }
  int previousMode = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4) = turnStateCode;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x10) = mode;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xc) = previousMode;
  PostMainWindowCommand100ForTurnFlow();
}

// TODO: port the per-turn global state machine (the large turn-advance dispatcher).
// FUNCTION: IMPERIALISM 0x0057da70
void TSimMgr::AdvanceGlobalTurnStateMachine() {}

// FUNCTION: IMPERIALISM 0x0057f110
int TSimMgr::IsTurnFlowPhaseOutsideRange4To5() {
  int phase = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4);
  return (phase <= 3) || (phase >= 6);
}

// TODO: port refresh of the eligible-nation turn-phase handlers.
// FUNCTION: IMPERIALISM 0x0057f140
void TSimMgr::RefreshEligibleNationTurnPhaseHandlers() {}

// TODO: port dispatch of the eligible-nation turn callback (+0x158).
// FUNCTION: IMPERIALISM 0x0057f200
void TSimMgr::DispatchEligibleNationTurnCallback158() {}

// TODO: port refresh of map systems / order-execution preparation.
// FUNCTION: IMPERIALISM 0x0057f280
void TSimMgr::RefreshMapSystemsAndPrepareOrderExecution() {}

// TODO: port dispatch of turn event 2134 and nation-panel refresh.
// FUNCTION: IMPERIALISM 0x0057f3c0
void TSimMgr::DispatchTurnEvent2134AndRefreshNationPanels() {}

// FUNCTION: IMPERIALISM 0x0057f490
int TSimMgr::ReturnZeroSlot6c() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057f4b0
void TSimMgr::MergeTurnFlowStatusFlags(unsigned int flags) {
  *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(this) + 0x3c) |= flags;
}

// TODO: port the "all active nations ready" scan over g_apNationStates.
// FUNCTION: IMPERIALISM 0x0057f4f0
int TSimMgr::AreAllActiveNationsReady() {
  return 0;
}

// TODO: port clearing of the per-nation ready flags.
// FUNCTION: IMPERIALISM 0x0057f530
void TSimMgr::ClearActiveNationReadyFlags() {}

// TODO: port signed-integer formatting with thousands separators.
// FUNCTION: IMPERIALISM 0x0057f5b0
void TSimMgr::FormatIntegerString(int, CString*) {}

// TODO: port the shared-string-from-bracket-expression formatter.
// FUNCTION: IMPERIALISM 0x0057f8f0
void TSimMgr::FormatOrdinalString(int, CString*) {}

// TODO: port the scenario-variant format trigger.
// FUNCTION: IMPERIALISM 0x0057fe90
void TSimMgr::TriggerScenarioVariantFormatSlot7c() {}

// TODO: port reseeding of the thread-local RNG from the wall clock.
// FUNCTION: IMPERIALISM 0x0057fec0
void TSimMgr::ReseedThreadLocalRandom() {}

// TODO: port the UI string loader (forwards to the app-context string resource lookup at
// 0x6a134c with offset+1).
// FUNCTION: IMPERIALISM 0x00580760
void TSimMgr::GetString(short, short, CString*) {}

// TODO: port diplomacy-notice text formatting by policy / grant code.
// FUNCTION: IMPERIALISM 0x00580790
void TSimMgr::FormatDiplomacyNoticeTextByPolicyOrGrantCode(CString*, short*) {}

#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x005811e0
int TSimMgr::GetField30(void) {
  return field30;
}

// FUNCTION: IMPERIALISM 0x00581200
#pragma optimize("y", on)
void TSimMgr::DecrementField30Value() {
  --field30;
}
#pragma optimize("", on)
