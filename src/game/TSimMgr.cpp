#include "game/TSimMgr.h"

#include <cstring>

#include "decomp_types.h"
#include "game/ImperialismApp.h"
#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TViewMgr.h"
#include "game/TTradeMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TArmyMgr.h"
#include "game/TOcean.h"
#include "game/TMapMgr.h"
#include "game/TTechMgr.h"
#include "game/TCivMgr.h"
#include "game/TTurnInstructionCursor.h"
#include "game/TNewsMgr.h"
#include "game/TNavyMgr.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TMinor.h"
#include "game/TRemoteGreatPower.h"
#include "game/TProxyGreatPower.h"
#include "game/TClientGreatPower.h"
#include "game/THostGreatPower.h"
#include "game/TRemoteMinor.h"
#include "game/TAnimator.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"

extern "C" char DAT_006a43c0;
extern "C" char DAT_006a43f0;
extern "C" const char s_PictWvGobPathFormat_00698BF4[];
void __fastcall RebuildNationStateSlotsAndAvailability_Impl(TSimMgr* self, int dummyEdx,
                                                            short* param_1);
void __fastcall RebuildCivilianOrderCompatibilityMatrices(TDiplomacyMgr* self, int dummyEdx);
int __cdecl TouchSessionActiveNationId(void);
void __cdecl ResetPortZoneGlobalContextCounters(void);
void RegenerateAllMapActionContextStatusCodes();
void __stdcall EnsurePictWvDataGobLoadedBySlot(int slotIndex);

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

// FUNCTION: IMPERIALISM 0x00415540
CString& __stdcall GetProfileStringFromSettingsSection(CString* result, LPCTSTR key,
                                                       LPCTSTR defaultValue) {
  *result = g_pImperialismApp->GetProfileString("Settings", key, defaultValue);
  return *result;
}

// FUNCTION: IMPERIALISM 0x004ee8c0
void __fastcall RebuildCivilianOrderCompatibilityMatrices(TDiplomacyMgr* self, int dummyEdx) {
  reinterpret_cast<void(__fastcall*)(TDiplomacyMgr*, int)>(0x004ee8c0)(self, dummyEdx);
}

// FUNCTION: IMPERIALISM 0x00519610
void __fastcall RebuildNationStateSlotsAndAvailability_Impl(TSimMgr* self, int dummyEdx,
                                                            short* param_1) {
  reinterpret_cast<void(__fastcall*)(TSimMgr*, int, short*)>(0x00519610)(self, dummyEdx, param_1);
}

// FUNCTION: IMPERIALISM 0x00549240
int __cdecl TouchSessionActiveNationId(void) {
  return reinterpret_cast<int(__cdecl*)()>(0x00549240)();
}

// FUNCTION: IMPERIALISM 0x005621b0
void __cdecl ResetPortZoneGlobalContextCounters(void) {
  reinterpret_cast<void(__cdecl*)()>(0x005621b0)();
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
  field44 = 0;
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
  turnStateCode = 1;
  runtimeSubsystemIndex = 0;
  field_64 = 0;
  field6e = 0;
  // Ten bytes 0x6f..0x78 (phaseFlags[9] + field78) are filled with 1 in one pass
  // (dword/dword/word stores in the original); field78 is then overwritten with 2.
  memset(phaseFlags, 0x01, sizeof(phaseFlags) + 1);
  field79 = 1;
  field78 = 2;
  // Developer-cheat probe: stat a file literally named "Conan" in the working directory;
  // the original discards the result and clears the cheat flag unconditionally (the flag
  // is armed elsewhere).
  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = 0;
  ReseedThreadLocalRandom();
  redrawEnabled = 0;
  InitializeOrLoadEntryArray14AndClampLimits(false);
  field6a = 0;
  field6c = 0x77a;
  gateFlag7a = 0;
}

// FUNCTION: IMPERIALISM 0x0057bd20
void TSimMgr::Free() {
  int i;
  if (g_pNationInteractionStateManager != nullptr) {
    g_pNationInteractionStateManager->Free();
    g_pNationInteractionStateManager = nullptr;
  }
  if (g_pDiplomacyTurnStateManager != nullptr) {
    g_pDiplomacyTurnStateManager->Free();
    g_pDiplomacyTurnStateManager = nullptr;
  }
  if (g_pMapContextActionManager != nullptr) {
    g_pMapContextActionManager->Free();
    g_pMapContextActionManager = nullptr;
  }
  if (g_pActiveMapOrderContext != nullptr) {
    g_pActiveMapOrderContext->Free();
    g_pActiveMapOrderContext = nullptr;
  }
  if (g_pGlobalMapState != nullptr) {
    g_pGlobalMapState->Free();
    g_pGlobalMapState = nullptr;
  }
  if (g_pCityOrderCapabilityState != nullptr) {
    g_pCityOrderCapabilityState->Free();
    g_pCityOrderCapabilityState = nullptr;
  }
  if (g_pInterNationEventQueueManager != nullptr) {
    reinterpret_cast<TNewsMgr*>(g_pInterNationEventQueueManager)->Free();
    g_pInterNationEventQueueManager = nullptr;
  }
  if (g_pSelectedCivilianOrderState != nullptr) {
    g_pSelectedCivilianOrderState->Free();
    g_pSelectedCivilianOrderState = nullptr;
  }
  if (g_pUiAnimator != nullptr) {
    g_pUiAnimator->Free();
    g_pUiAnimator = nullptr;
  }
  if (g_pNavyOrderManager != nullptr) {
    g_pNavyOrderManager->Free();
    g_pNavyOrderManager = nullptr;
  }

  for (i = 0; i < 0x17; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
      g_apTerrainTypeDescriptorTable[i]->Free();
    }
    g_apTerrainTypeDescriptorTable[i] = nullptr;
  }

  for (i = 0; i < 7; ++i) {
    g_apNationStates[i] = nullptr;
  }

  for (i = 7; i < 0x17; ++i) {
    g_apSecondaryNationStateSlots[i] = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0057bea0
void TSimMgr::ReadFrom(TStream* stream) {
  int i;
  if (g_nSaveFormatVersion < 0x38) {
    short quarters;
    short years;
    stream->ReadBytes(&quarters, 2);
    stream->ReadBytes(&years, 2);
    quarterGateTick2c = quarters + years * 4;
  } else {
    stream->ReadBytes(&quarterGateTick2c, 2);
  }

  stream->ReadBytes(&activeNationSlot, 2);
  stream->ReadBytes(&turnStateCode, 2);
  stream->ReadBytes(&mode, 2);
  stream->ReadBytes(&previousTurnStateCode, 2);
  stream->ReadBytes(&previousMode, 2);
  stream->ReadBytes(&field14, 1);
  stream->ReadBytes(&field30, 4);
  stream->ReadBytes(&field34, 4);
  stream->ReadBytes(&turnFlowStatusFlags, 4);

  if (g_nSaveFormatVersion >= 0x20) {
    runtimeSubsystemIndex = stream->ReadInteger() & 0xff;
  }

  if (g_nSaveFormatVersion < 0x2d) {
    stream->ReadBytes(&fieldd8, 0x3c);
    stateFlag114 = 0;
  } else {
    stream->ReadBytes(&fieldd8, 0x3e);
  }

  if (g_nSaveFormatVersion < 0x2e) {
    field_64 = 0x2711;
  } else {
    stream->ReadBytes(&field_64, 4);
  }

  stream->ReadBytes(&field15, 0x17);

  int dummy;
  stream->ReadBytes(&dummy, 4);

  if (field44 != 0) {
    g_pGameFlowState->ReadFrom(stream);
  }

  if (g_nSaveFormatVersion >= 0x24) {
    stream->ReadBytes(&preferenceValues[10], 2);
  }

  short temp_6a = 0;
  if (g_nSaveFormatVersion >= 0x34) {
    stream->ReadBytes(&temp_6a, 2);
    field6a = temp_6a;
  } else {
    field6a = (stateFlag114 != 0) ? 1 : 0;
  }

  EnsurePictWvDataGobLoadedBySlot(field6a);
  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();

  if (g_nSaveFormatVersion >= 0x36) {
    stream->ReadBytes(&field6c, 2);
  }

  if (g_nSaveFormatVersion < 0x3b) {
    field6e = 0;
    memset(phaseFlags, 0x01, 10);
    field79 = 1;
    field6e = 0;
    (&field6e)[(field6c - 0x717) / 10] = 2;
  } else {
    stream->ReadBytes(&field6e, 0xc);
  }

  for (i = 0; i < 0x17; ++i) {
    sharedTextSlots[i] = g_szEmptyString;
  }

  if (g_nSaveFormatVersion >= 0x3c) {
    for (i = 0; i < 0x17; ++i) {
      stream->streamSlot70(&sharedTextSlots[i], 0x20);
    }
  }

  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(1);
  RebuildGlobalOrderManagersAndCapabilityState(0);
  RebuildMapContextAndGlobalMapState(0, nullptr, 0);
  RebuildNationStateSlotsAndAvailability(0);

  field14 = 4;
  RebuildNationStateSlotsNoOp();
}

// FUNCTION: IMPERIALISM 0x0057c230
void TSimMgr::WriteTo(TStream* stream) {
  int i;
  stream->WriteBytesSlot78(&quarterGateTick2c, 2);
  stream->WriteBytesSlot78(&activeNationSlot, 2);
  stream->WriteBytesSlot78(&turnStateCode, 2);
  stream->WriteBytesSlot78(&mode, 2);
  stream->WriteBytesSlot78(&previousTurnStateCode, 2);
  stream->WriteBytesSlot78(&previousMode, 2);
  stream->WriteBytesSlot78(&field14, 1);
  stream->WriteBytesSlot78(&field30, 4);
  stream->WriteBytesSlot78(&field34, 4);
  stream->WriteBytesSlot78(&turnFlowStatusFlags, 4);
  stream->streamSlot7c(static_cast<unsigned char>(runtimeSubsystemIndex));
  stream->WriteBytesSlot78(&fieldd8, 0x3e);
  stream->WriteBytesSlot78(&field_64, 4);
  stream->WriteBytesSlot78(&field15, 0x17);
  stream->WriteBytesSlot78(&field44, 4);

  if (field44 != 0) {
    g_pGameFlowState->WriteTo(stream);
  }

  stream->WriteBytesSlot78(&preferenceValues[10], 2);
  stream->WriteBytesSlot78(&field6a, 2);
  stream->WriteBytesSlot78(&field6c, 2);
  stream->WriteBytesSlot78(&field6e, 0xc);

  for (i = 0; i < 0x17; ++i) {
    stream->streamSlotAc(&sharedTextSlots[i]);
  }
}

// FUNCTION: IMPERIALISM 0x0057c390
void TSimMgr::RebuildNationStateSlotsNoOp() {}

// FUNCTION: IMPERIALISM 0x0057c3b0
void TSimMgr::RebuildGlobalOrderManagersAndCapabilityState(char flag) {
  int i;
  if (((flag != 0) && (DAT_006a43f0 == 0)) || ((flag == 0) && (DAT_006a43f0 != 0))) {
    if (flag != 0) {
      short* destCursor = scenarioSetupRows1;
      const short* srcCursor = g_anScenarioNationSetupTable_00698B1A;
      for (i = 0; i < 7; ++i) {
        destCursor[-7] = srcCursor[-1];
        destCursor[0] = srcCursor[0];
        destCursor[7] = srcCursor[1];
        destCursor[14] = srcCursor[2];
        destCursor += 1;
        srcCursor += 4;
      }
      fieldd8 = 0;
      field112 = 0;
    }

    field30 = 0;
    fieldd8 = (field44 != 0) ? 1 : 0;
    for (i = 0; i < 7; ++i) {
      if (field15[i] != 0) {
        field30++;
      }
    }

    field34 = 0;
    for (i = 7; i < 0x17; ++i) {
      if (field15[i] != 0) {
        field34++;
      }
    }

    if (g_pUiAnimator != nullptr) {
      g_pUiAnimator->Free();
      g_pUiAnimator = nullptr;
    }
    g_pUiAnimator = new TAnimator();
    g_pUiAnimator->InitializeUiTransientObjectRegistry(0x7fffffff);

    if (g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->Free();
      g_pDiplomacyTurnStateManager = nullptr;
    }
    g_pDiplomacyTurnStateManager = new TDiplomacyMgr();

    if (g_pNationInteractionStateManager != nullptr) {
      g_pNationInteractionStateManager->Free();
      g_pNationInteractionStateManager = nullptr;
    }
    g_pNationInteractionStateManager = new TTradeMgr();

    if (g_pInterNationEventQueueManager != nullptr) {
      reinterpret_cast<TNewsMgr*>(g_pInterNationEventQueueManager)->Free();
      g_pInterNationEventQueueManager = nullptr;
    }
    g_pInterNationEventQueueManager =
        reinterpret_cast<TInterNationEventQueueManager*>(new TNewsMgr());

    if (g_pMapContextActionManager != nullptr) {
      g_pMapContextActionManager->Free();
      g_pMapContextActionManager = nullptr;
    }
    g_pMapContextActionManager = new TArmyMgr();

    if (g_pSelectedCivilianOrderState != nullptr) {
      g_pSelectedCivilianOrderState->Free();
      g_pSelectedCivilianOrderState = nullptr;
    }
    g_pSelectedCivilianOrderState = new TCivMgr();

    if (g_pNavyOrderManager != nullptr) {
      g_pNavyOrderManager->Free();
      g_pNavyOrderManager = nullptr;
    }
    g_pNavyOrderManager = new TNavyMgr();

    if (g_pCityOrderCapabilityState != nullptr) {
      g_pCityOrderCapabilityState->Free();
      g_pCityOrderCapabilityState = nullptr;
    }
    g_pCityOrderCapabilityState = new TTechMgr();
  }
}

// FUNCTION: IMPERIALISM 0x0057c7c0
void TSimMgr::RebuildMapContextAndGlobalMapState(int arg1, const char* arg2, int arg3) {
  int i;
  if (DAT_006a43f0 == 0) {
    CString local_10;
    for (i = 0; i < 0x17; ++i) {
      SetSharedStringFromMappedFlavorTextWithLengthClamp(&local_10, i);
      sharedTextSlots[i] = local_10;
    }
  }

  if (arg1 != 0) {
    if (DAT_006a43f0 != 0) {
      return;
    }
  }

  if (g_pActiveMapOrderContext != nullptr) {
    g_pActiveMapOrderContext->Free();
    g_pActiveMapOrderContext = nullptr;
  }

  g_pActiveMapOrderContext = new TOcean();

  ResetPortZoneGlobalContextCounters();

  if (g_pGlobalMapState != nullptr) {
    g_pGlobalMapState->Free();
    g_pGlobalMapState = nullptr;
  }

  g_pGlobalMapState = new TMapMgr();
  g_pGlobalMapState->InitializeGlobalMapState();

  if (DAT_006a43f0 == 0) {
    g_pGlobalMapState->hexNeighborWrapHorizontally20 = static_cast<char>(arg3);
    g_pGlobalMapState->BuildOrLoadGlobalMapStateForSession(arg2, nullptr);
  } else {
    g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
  }
}

// FUNCTION: IMPERIALISM 0x0057c9a0
unsigned char TSimMgr::RecreateActiveMapContextAndInitializeGlobalMapState(int scenarioIndex) {
  stateFlag114 = static_cast<short>(scenarioIndex + 1);

  if (g_pActiveMapOrderContext != nullptr) {
    g_pActiveMapOrderContext->Free();
    g_pActiveMapOrderContext = nullptr;
  }
  g_pActiveMapOrderContext = new TOcean();
  ResetPortZoneGlobalContextCounters();

  if (g_pGlobalMapState != nullptr) {
    g_pGlobalMapState->Free();
    g_pGlobalMapState = nullptr;
  }
  g_pGlobalMapState = new TMapMgr();
  g_pGlobalMapState->InitializeGlobalMapState();
  g_pGlobalMapState->hexNeighborWrapHorizontally20 = 1;
  return static_cast<unsigned char>(
      g_pGlobalMapState->BuildOrLoadGlobalMapStateForSession(g_szEmptyString, g_szEmptyString));
}

// FUNCTION: IMPERIALISM 0x0057cad0
void TSimMgr::RebuildNationStateSlotsAndAvailability(int activate) {
  int i;
  if (DAT_006a43f0 == 0) {
    short local_1c[8];
    RebuildNationStateSlotsAndAvailability_Impl(this, 0, local_1c);

    for (i = 0; i < 7; ++i) {
      int val = local_1c[i];
      scenarioSetupRows1[i] = g_anScenarioNationSetupTable_00698B1A[val * 4];
      scenarioSetupRows2[i] = g_anScenarioNationSetupTable_00698B1A[val * 4 + 1];
      scenarioSetupRows3[i] = g_anScenarioNationSetupTable_00698B1A[val * 4 + 2];
    }
  }

  if (field44 != 0) {
    for (i = 0; i < 7; ++i) {
      int activeSessionId = g_pGameFlowState->nationSessionIds[i];
      int activeNationId = TouchSessionActiveNationId();
      if (activeSessionId == activeNationId) {
        scenarioSetupRows0[i] = 1;
      } else if (field44 == 2) {
        scenarioSetupRows0[i] = 4;
      } else {
        scenarioSetupRows0[i] = (activeSessionId != 0) ? 3 : 2;
      }
    }
  }

  for (i = 6; i >= 0; --i) {
    if (field15[i] == 0) {
      g_apNationStates[i] = nullptr;
      g_apTerrainTypeDescriptorTable[i] = nullptr;
    } else {
      RebuildPrimaryNationStateForSlot(i, activate);
    }
  }

  for (i = 0; i < 0x17; ++i) {
    if (field15[i] == 0) {
      g_apSecondaryNationStateSlots[i] = nullptr;
      g_apTerrainTypeDescriptorTable[i] = nullptr;
    } else {
      RebuildSecondaryNationStateForSlot(i);
    }
  }

  if (DAT_006a43f0 == 0) {
    RebuildCivilianOrderCompatibilityMatrices(g_pDiplomacyTurnStateManager, 0);
    g_pUiRuntimeContext->InvokeStrategicMapViewMethod74();
    g_pCityOrderCapabilityState->GenerateRandomCapabilityPrioritySlots();
    g_pGlobalMapState->RefreshMapContextRotatingStatusStrings();
    RegenerateAllMapActionContextStatusCodes();
    g_pInterNationEventQueueManager->QueueInterNationEventType11(999, 1, 1);
    g_pInterNationEventQueueManager->QueueInterNationEventType11(999, 2, 1);

    const char* tagText = g_pGlobalMapState->scenarioTagText1c;
    if (tagText[0] == '.') {
      CString path;
      path.Format(s_PictWvGobPathFormat_00698BF4, tagText[1] - '0');
      if (TryGetFileMetadataForPath(&path)) {
        EnsurePictWvDataGobLoadedBySlot(tagText[1] - '0');
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057cda0
void TSimMgr::RebuildPrimaryNationStateForSlot(int slotIndex, char activate) {
  if (g_apNationStates[slotIndex] != nullptr) {
    g_apNationStates[slotIndex]->Free();
  }
  g_apNationStates[slotIndex] = nullptr;
  g_apTerrainTypeDescriptorTable[slotIndex] = nullptr;

  short sVar1 = scenarioSetupRows0[slotIndex];
  if (sVar1 != 1) {
    if (sVar1 == 4) {
      TGreatPower* pTVar5 = (TGreatPower*)new TRemoteGreatPower();
      g_apNationStates[slotIndex] = pTVar5;
      pTVar5->InitializeNationStateRuntimeSubsystems(
          g_pGameFlowState->nationSessionIds[slotIndex] != 0, 1);
      g_apTerrainTypeDescriptorTable[slotIndex] = pTVar5;

      g_apTerrainTypeDescriptorTable[slotIndex]->identitySharedString1 =
          g_pGameFlowState->nationDisplayNameSlots[slotIndex];

      if (activate != 0 && stateFlag114 != 0) {
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(pTVar5->city);
      }
    } else if (sVar1 == 3) {
      TGreatPower* pTVar5 = (TGreatPower*)new TProxyGreatPower();
      pTVar5->InitializeNationStateRuntimeSubsystems(1, 1);
      g_apNationStates[slotIndex] = pTVar5;
      g_apTerrainTypeDescriptorTable[slotIndex] = pTVar5;

      if (DAT_006a43f0 == 0) {
        if (activate != 0) {
          pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(pTVar5->city);
        }
        g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(slotIndex, slotIndex, 0x100);
      }
      g_apTerrainTypeDescriptorTable[slotIndex]->identitySharedString1 =
          g_pGameFlowState->nationDisplayNameSlots[slotIndex];
    } else if (sVar1 == 2) {
      TGreatPower* pTVar5 = new TGreatPower();
      pTVar5->InitializeNationMinisterSubsystemsByPolicyIds(
          slotIndex, 2, scenarioSetupRows1[slotIndex], scenarioSetupRows2[slotIndex],
          scenarioSetupRows3[slotIndex]);
      g_apNationStates[slotIndex] = pTVar5;
      g_apTerrainTypeDescriptorTable[slotIndex] = pTVar5;

      if (DAT_006a43f0 == 0) {
        if (activate != 0) {
          pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(pTVar5->city);
        }
        pTVar5->QueueMapActionMissionsForPortZoneCandidates();
        pTVar5->AssignDisplayNamesToUnnamedMilitaryUnits();
      }
    } else {
      g_apNationStates[slotIndex] = nullptr;
      g_apTerrainTypeDescriptorTable[slotIndex] = nullptr;
    }
  } else {
    if (field44 == 2) {
      TGreatPower* pTVar5 = (TGreatPower*)new TClientGreatPower();
      g_apNationStates[slotIndex] = pTVar5;
    } else if (field44 == 1) {
      TGreatPower* pTVar5 = (TGreatPower*)new THostGreatPower();
      g_apNationStates[slotIndex] = pTVar5;
    } else {
      TGreatPower* pTVar5 = new TGreatPower();
      g_apNationStates[slotIndex] = pTVar5;
    }
    g_apNationStates[slotIndex]->InitializeNationStateRuntimeSubsystems(1, 1);
    g_apTerrainTypeDescriptorTable[slotIndex] = g_apNationStates[slotIndex];
    if (DAT_006a43f0 == 0) {
      activeNationSlot = static_cast<short>(slotIndex);
      g_pStrategicMapViewSystem->RefreshCityCapabilityUiHandlesForActiveNation();
    }
    if (DAT_006a43f0 == 0) {
      if (field44 != 0) {
        g_pGameFlowState->processPrimaryEventQueue = 0;
      }
      if (activate != 0) {
        g_apNationStates[slotIndex]->ApplyScenarioRelationPresetAndSpawnFrogCity(
            g_apNationStates[slotIndex]->city);
      }
      if (field44 != 0) {
        g_pGameFlowState->processPrimaryEventQueue = 1;
      }
    }
  }

  if (slotIndex == activeNationSlot) {
    if (field44 == 0) {
      g_apTerrainTypeDescriptorTable[slotIndex]->identitySharedString1 =
          g_cstrCountryNameSettingValue006A4220;
    } else {
      g_apTerrainTypeDescriptorTable[slotIndex]->identitySharedString1 =
          g_pGameFlowState->nationDisplayNameSlots[slotIndex];
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057d520
void TSimMgr::RebuildSecondaryNationStateForSlot(int slotIndex) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(0x0057d520)(this, 0, slotIndex);
}

// FUNCTION: IMPERIALISM 0x0057d830
void TSimMgr::ApplyScenarioVariantSeedForNationSetup(CString* destString) {
  short offset = quarterGateTick2c % 4;
  GetString(10000, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0057d870
void TSimMgr::SetStateCodeAndUpdateZeroOrOutOfRangeFlag(int stateCode) {
  char zeroFlag = 0;
  this->redrawEnabled = stateCode;
  if (stateCode != 0) {
    if (0 < stateCode && stateCode <= 4) {
      this->preferenceValues[10] = 0;
      return;
    }
  } else {
    zeroFlag = 1;
  }
  this->preferenceValues[10] = zeroFlag;
}

// FUNCTION: IMPERIALISM 0x0057d8b0
short TSimMgr::GetTurnTickSlot3C() {
  return quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x0057d8d0
void TSimMgr::CopyScenarioNationSetupIntoFlowState(void* setupBuffer) {
  struct ScenarioSetupBuffer {
    unsigned char flagD8;
    unsigned char padding;
    short nationSetup[4][7];
    unsigned char flag112;
  };
  const ScenarioSetupBuffer* buf = static_cast<const ScenarioSetupBuffer*>(setupBuffer);

  for (int i = 0; i < 7; ++i) {
    scenarioSetupRows0[i] = buf->nationSetup[0][i];
    scenarioSetupRows1[i] = buf->nationSetup[1][i];
    scenarioSetupRows2[i] = buf->nationSetup[2][i];
    scenarioSetupRows3[i] = buf->nationSetup[3][i];
  }

  fieldd8 = buf->flagD8;
  if (buf->flag112 != 0) {
    field112 = 1;
  }
}

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

// FUNCTION: IMPERIALISM 0x00580760
void TSimMgr::GetString(short codeGroup, short offset, CString* destString) {
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(destString, codeGroup,
                                                                  offset + 1);
}

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

// FUNCTION: IMPERIALISM 0x00581280
char TSimMgr::IsNationSlotEligibleForEventProcessing(short nationSlot) {
  if (nationSlot == -1) {
    return 0;
  }

  TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
  if (terrainDescriptor == 0) {
    return 0;
  }

  if (nationSlot < 7) {
    if (terrainDescriptor != 0) {
      short profileType = terrainDescriptor->encodedNationSlot;
      char inReservedProfileBand = profileType >= 100 && profileType < 200;
      if (inReservedProfileBand) {
        return 0;
      }
    }
  }

  return 1;
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

// The "Done/advance" turn-flow bootstrap primitive (free __cdecl in the TSimMgr TU): the
// single writer of DAT_006a43c0 and the funnel every menu/score-screen advance routes
// through. eventCode 0x5dd is the "start new game" scenario-setup path: it soft-resets
// the EXISTING TSimMgr (the reset block is the original's header-inline prefix of
// InitializeTurnFlowStateDefaults, expanded in place at 0x58191a) and jumps the turn
// state machine to state 3. Every other code tears the manager down and rebuilds it
// from scratch.
// FUNCTION: IMPERIALISM 0x00581870
void ReinitializeGameFlowAndPostTurnEventCode(int eventCode) {
  if (g_pHelpMgr != 0) {
    g_pHelpMgr->HandlePendingEventActivationByCode(0x5dc);
  }
  if (g_pSimMgr->field44 != 0) {
    g_pGameFlowState->Free();
    g_pGameFlowState = new TMultiplayerMgr();
    g_pGameFlowState->InitializeMultiplayerManagerForSessionContext(0);
  }
  if (eventCode == 0x5dd) {
    TSimMgr* simMgr = g_pSimMgr;
    simMgr->quarterGateTick2c = 0;
    simMgr->activeNationSlot = -1;
    simMgr->field14 = 0;
    simMgr->turnStateCode = 1;
    simMgr->runtimeSubsystemIndex = 0;
    simMgr->field_64 = 0;
    simMgr->field6e = 0;
    memset(simMgr->phaseFlags, 0x01, sizeof(simMgr->phaseFlags) + 1);
    simMgr->field79 = 1;
    simMgr->field78 = 2;
    CFileStatus conanFileStatus;
    CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
    g_bRandomMapDeveloperCheatFlag = 0;
    simMgr->ReseedThreadLocalRandom();
    g_pSimMgr->turnStateCode = 3;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(static_cast<short>(eventCode));
  } else {
    g_pSimMgr->Free();
    g_pSimMgr = new TSimMgr();
    g_pSimMgr->InitializeTurnFlowStateDefaults();
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    if (eventCode != 0) {
      g_pGlobalUiRootController->PostTurnEventCodeMessage2420(static_cast<short>(eventCode));
    }
  }
  DAT_006a43c0 = 1;
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

// FUNCTION: IMPERIALISM 0x00581bc0
CString TSimMgr::AssignSharedStringFromIndexedSlot7C(short slot) {
  return sharedTextSlots[slot];
}

// Reads a big-endian 32-bit nation slot then a big-endian short transport-capacity value,
// stored into that nation's needCapA6 field.
// FUNCTION: IMPERIALISM 0x00582860
void TSimMgr::HandleTurnInstruction_Tran_SetNationTransportStat(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* nraw = reinterpret_cast<unsigned char*>(&nationToken);
  unsigned char nt = nraw[0];
  nraw[0] = nraw[3];
  nraw[3] = nt;
  nt = nraw[1];
  nraw[1] = nraw[2];
  nraw[2] = nt;

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  g_apNationStates[static_cast<int>(nationToken)]->needCapA6 = static_cast<short>(valueToken);
}

// Reads one big-endian short token (the scenario year) and stores it, scaled to quarter
// ticks (year * 4), into the turn-flow tick field at +0x2c.
// FUNCTION: IMPERIALISM 0x00582ed0
void TSimMgr::HandleTurnInstruction_Year_UpdateScenarioYearFieldScaledBy4(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token = *cursor;
  instruction->tokenCursor = cursor + 1;
  unsigned char* raw = reinterpret_cast<unsigned char*>(&token);
  raw[0] = raw[3];
  raw[1] = raw[2];
  quarterGateTick2c = static_cast<short>(token) * 4;
}

// Reads two big-endian 32-bit tokens (nation slot, then cash amount) and writes the amount
// into that nation's treasury field.
// FUNCTION: IMPERIALISM 0x00583360
void TSimMgr::HandleTurnInstruction_Cash_SetNationCash(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* nraw = reinterpret_cast<unsigned char*>(&nationToken);
  unsigned char nt = nraw[0];
  nraw[0] = nraw[3];
  nraw[3] = nt;
  nt = nraw[1];
  nraw[1] = nraw[2];
  nraw[2] = nt;

  unsigned int cashToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* craw = reinterpret_cast<unsigned char*>(&cashToken);
  unsigned char ct = craw[0];
  craw[0] = craw[3];
  craw[3] = ct;
  ct = craw[1];
  craw[1] = craw[2];
  craw[2] = ct;

  g_apNationStates[static_cast<int>(nationToken)]->treasuryValue10 = static_cast<int>(cashToken);
}

// Reads one big-endian short token (a nation flag/language index), stores it into the
// selected-index field, and refreshes the picture-word-data language pack + strategic map
// bitmap cache (the inlined body of SetSelectedIndex6AAndTriggerRefresh).
// FUNCTION: IMPERIALISM 0x00583400
void TSimMgr::HandleTurnInstruction_Flag_SetNationFlagAndRefresh(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token = *cursor;
  instruction->tokenCursor = cursor + 1;
  unsigned char* raw = reinterpret_cast<unsigned char*>(&token);
  raw[0] = raw[3];
  raw[1] = raw[2];
  short index = static_cast<short>(token);
  field6a = index;
  EnsurePictWvDataGobLoadedBySlot(index);
  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();
}

// FUNCTION: IMPERIALISM 0x005837c0
void TSimMgr::SetActiveNationSlotAndRefreshCityCapabilityUiHandles(short nationSlot) {
  activeNationSlot = nationSlot;
  g_pStrategicMapViewSystem->RefreshCityCapabilityUiHandlesForActiveNation();
}

// FUNCTION: IMPERIALISM 0x005d4c10
unsigned char __cdecl TryGetFileMetadataForPath(CString* path) {
  CFileStatus status;
  // Callers branch on AL: the original returns a Mac-style byte Boolean, not BOOL.
  return (unsigned char)CFile::GetStatus(*path, status);
}

// FUNCTION: IMPERIALISM 0x005d4c40
void __cdecl DeleteFileWithErrorReporting(CString* path) {
  CFile::Remove(*path);
}

// FUNCTION: IMPERIALISM 0x005e01a0
void __stdcall LoadProfileStringAndAssignSharedRef(CString* outString, LPCTSTR key,
                                                   LPCTSTR defaultValue) {
  CString result;
  GetProfileStringFromSettingsSection(&result, key, defaultValue);
  *outString = result;
}

// FUNCTION: IMPERIALISM 0x005e0260
void SaveSettingValueFromPointerByKey(CString* value, const char* key) {
  g_pImperialismApp->SetSettingValueInSettingsSection(key, *value);
}
