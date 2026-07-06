#include "game/TSimMgr.h"

#include <cstring>

#include "decomp_types.h"
#include "game/ImperialismApp.h"
#include "game/TAssetMgr.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/TMacViewMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x004153a0
int ReadSettingsPrefIntByIndex(int index, int defaultValue) {
  CString key;
  key.Format("Pref%d", index);
  return g_pImperialismApp->GetProfileInt("Settings", key, defaultValue);
}

// FUNCTION: IMPERIALISM 0x00415440
void WriteSettingsPrefIntByIndex(int index, int value) {
  CString key;
  key.Format("Pref%d", index);
  g_pImperialismApp->WriteProfileInt("Settings", key, value);
}
// SYNTHETIC: IMPERIALISM 0x0057b940
// TSimMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0057b9c0
// TSimMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSimMgr, TObject)

// FUNCTION: IMPERIALISM 0x0057b9e0
TSimMgr::TSimMgr() : sharedTextSlots() {
  turnStateCode = 1;
  mode = 1;
  previousTurnStateCode = 1;
  previousMode = 1;
  field14 = 0;

  // Fused loop: fill field15[0..0x16] with 1 AND assign g_szEmptyString to each shared-text
  // slot. Mirrors the original single do-while at 0x57ba44..0x57ba7b.
  for (int i = 0; i < 0x17; ++i) {
    field15[i] = 1;
    CString empty(g_szEmptyString); // temp -> 0x00605950, ~ -> 0x006058e2
    sharedTextSlots[i] = empty;     // -> 0x00605a29 CString::operator=
  }

  quarterGateTick2c = 0;
  activeNationSlot = -1;
  field30 = 7;
  field34 = 0x10;

  // Copy the per-nation scenario setup table (DAT_00698b1a) into the four contiguous
  // scenarioSetupRows arrays. The original reads 4 shorts per iteration at table[-1..2]
  // with stride 4, scattering them via one cursor anchored at scenarioSetupRows1
  // (+0xe8): [-7] hits rows0, [0] rows1, [7] rows2, [14] rows3.
  short* destCursor = scenarioSetupRows1;
  const short* tableCursor = g_anScenarioNationSetupTable_00698B1A;
  for (int row = 0; row < 7; ++row) {
    destCursor[-7] = tableCursor[-1];
    destCursor[0] = tableCursor[0];
    destCursor[7] = tableCursor[1];
    destCursor[14] = tableCursor[2];
    destCursor += 1;
    tableCursor += 4;
  }

  fieldd8 = 0;
  field112 = 0;
  stateFlag114 = 0;
  preferenceValues[0] = 0;
  preferenceValues[1] = 0;
}

// SYNTHETIC: IMPERIALISM 0x0057bb50
// TSimMgr::`scalar deleting destructor'
TSimMgr::~TSimMgr() {}

// TODO: port teardown of the global map/order-manager singletons and nation-state tables
// (overrides TObject::Free; releases g_pNationInteractionStateManager,
// g_pDiplomacyTurnStateManager, g_pMapContextActionManager, ... via their own vtables).

// FUNCTION: IMPERIALISM 0x0057bbf0
void TSimMgr::InitializeTurnFlowStateDefaults() {
  quarterGateTick2c = 0;
  activeNationSlot = -1;
  field14 = 0;
  mode = 1;
  turnFlowStatusFlags = 0;
  field_64 = 0;
  field6e = 0;
  memset(phaseFlags, 0x01, sizeof(phaseFlags));
  gateFlag7a = 0;
  field78 = 2;
  field79 = 1;
  g_apSecondaryNationStateSlots[0x17] = nullptr;
  PostMainWindowCommand100ForTurnFlow();
  runtimeSubsystemIndex = 0;
  InitializeOrLoadEntryArray14AndClampLimits(false);
  field6a = 0;
  field6c = 0x77a;
}

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

// TODO: port the order-manager/capability-state rebuild (writes scenarioSetupRows
// regions at +0xe8, gated on flag and DAT_006a43f0).

// FUNCTION: IMPERIALISM 0x0057c3b0
void TSimMgr::RebuildGlobalOrderManagersAndCapabilityState(char) {}

// TODO: port the map-context/global-map-state rebuild.

// FUNCTION: IMPERIALISM 0x0057c7c0
void TSimMgr::RebuildMapContextAndGlobalMapState(int, const char*, int) {}

// TODO: port the nation-state slot table rebuild.

// FUNCTION: IMPERIALISM 0x0057cad0
void TSimMgr::RebuildNationStateSlotsAndAvailability(int) {}

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

// FUNCTION: IMPERIALISM 0x0057d870
void TSimMgr::SetStateCodeAndUpdateZeroOrOutOfRangeFlag(int stateCode) {
  char zeroFlag = 0;
  this->redrawEnabled = stateCode;
  if (stateCode != 0) {
    if (0 < stateCode && stateCode <= 4) {
      this->preferenceValues[12] = 0;
      return;
    }
  } else {
    zeroFlag = 1;
  }
  this->preferenceValues[12] = zeroFlag;
}

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
  g_pImperialismApp->PostStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x0057d990
void TSimMgr::SetGlobalTurnStateCodeIfAllowed(int turnStateCode) {
  short nationSlot = activeNationSlot;
  bool allowStateChange;
  if (nationSlot == -1) {
    allowStateChange = false;
  } else {
    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
    if (terrainDescriptor == 0) {
      allowStateChange = false;
    } else {
      if (nationSlot < 7) {
        short field0e = terrainDescriptor->encodedNationSlot;
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
  int previousMode = this->turnStateCode;
  this->turnStateCode = turnStateCode;
  this->previousMode = mode;
  previousTurnStateCode = previousMode;
  PostMainWindowCommand100ForTurnFlow();
}

// TSimMgr::AdvanceGlobalTurnStateMachine (0x0057da70) is defined in its own translation unit,
// src/game/TSimMgr_AdvanceGlobalTurnStateMachine.cpp, so its large inline switch body does not
// perturb the codegen of the methods in this file.

// FUNCTION: IMPERIALISM 0x0057f110
int TSimMgr::IsTurnFlowPhaseOutsideRange4To5() {
  int phase = turnStateCode;
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
  turnFlowStatusFlags |= flags;
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

// FUNCTION: IMPERIALISM 0x005811e0
int TSimMgr::GetField30(void) {
  return field30;
}

// FUNCTION: IMPERIALISM 0x00581200
void TSimMgr::DecrementField30Value() {
  --field30;
}

// FUNCTION: IMPERIALISM 0x00581260
short TSimMgr::GetActiveNationId() {
  return activeNationSlot;
}

// FUNCTION: IMPERIALISM 0x00581400
void TSimMgr::InitializeOrLoadEntryArray14AndClampLimits(bool writeBack) {
  if (writeBack) {
    for (int writeIndex = 0; writeIndex < 14; ++writeIndex) {
      WriteSettingsPrefIntByIndex(writeIndex, preferenceValues[writeIndex]);
    }
    preferenceValues[12] = 0;
    preferenceValues[1] = 0;
    return;
  }

  for (int initIndex = 0; initIndex < 14; ++initIndex) {
    preferenceValues[initIndex] = 0x101;
  }
  preferenceValues[10] = 0;
  preferenceValues[0] = 0;
  preferenceValues[11] = 0;
  preferenceValues[3] = 0xff;
  preferenceValues[2] = 100;

  for (int readIndex = 0; readIndex < 14; ++readIndex) {
    preferenceValues[readIndex] =
        static_cast<short>(ReadSettingsPrefIntByIndex(readIndex, preferenceValues[readIndex]));
  }

  if (preferenceValues[3] < 0) {
    preferenceValues[3] = 0;
  }
  if (preferenceValues[2] < 0) {
    preferenceValues[2] = 0;
  }
  if (preferenceValues[3] > 0xff) {
    preferenceValues[3] = 0xff;
  }
  if (preferenceValues[2] > 100) {
    preferenceValues[2] = 100;
  }
  preferenceValues[12] = 0;
  preferenceValues[1] = 0;
}

// FUNCTION: IMPERIALISM 0x00581ae0
void TSimMgr::SetSelectedIndex6AAndTriggerRefresh(short index) {
  field6a = index;
  EnsurePictWvDataGobLoadedBySlot(index);
  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();
}

// FUNCTION: IMPERIALISM 0x00581b20
CString* TSimMgr::LoadNormalizedCredentialName(CString* out, short slot) {
  *out = sharedTextSlots[slot];
  return out;
}
