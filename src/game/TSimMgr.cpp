#include "game/TAmbitApplication.h"
#include "game/TSimMgr.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif

#include <cstring>
#include <ctime>
#include <stdio.h>
#include <stdlib.h>

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
#include "game/navy_order.h"
#include "game/TViewMgr.h"
#include "game/TTradeMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TArmyMgr.h"
#include "game/TOcean.h"
#include "game/TMapMgr.h"
#include "game/TTechMgr.h"
#include "game/TCity.h"
#include "game/TCityInteriorMinister.h"
#include "game/TCivMgr.h"
#include "game/TCivUnit.h"
#include "game/TTurnInstructionCursor.h"
#include "game/TNewsMgr.h"
#include "game/TNetMgr.h"
#include "game/TNavyMgr.h"
#include "game/TNewsMgr.h"
#include "game/TMinor.h"
#include "game/TMilitaryUnit.h"
#include "game/TAutoGreatPower.h"
#include "game/TRemoteGreatPower.h"
#include "game/TProxyGreatPower.h"
#include "game/TClientGreatPower.h"
#include "game/THostGreatPower.h"
#include "game/TRemoteMinor.h"
#include "game/TAnimator.h"
#include "game/TLanguageMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"

int __cdecl TouchSessionActiveNationId(void);
void __cdecl ResetPortZoneGlobalContextCounters(void);
void RegenerateAllMapActionContextStatusCodes();

static inline bool IsNationEligibleForOptionalPhase(short nationSlot) {
  if (nationSlot == -1) {
    return false;
  }
  TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
  if (country == nullptr) {
    return false;
  }
  if (nationSlot >= 7) {
    return true;
  }
  const short profileCode = country->encodedNationSlot;
  return profileCode < 100 || profileCode >= 200;
}

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

// FUNCTION: IMPERIALISM 0x00549240
int __cdecl TouchSessionActiveNationId(void) {
  return g_pNetMgr006a6014->GetSessionActiveNationId();
}

// FUNCTION: IMPERIALISM 0x005621b0
void __cdecl ResetPortZoneGlobalContextCounters(void) {
  g_nMapActionContextCount = 0;
  g_nMapActionContextDistanceCacheSizedFor = -1;
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

  economicTurn = 0;
  activeNationSlot = -1;
  numGreatPowers = 7;
  numMinorCountries = 0x10;

  // Copy the four-column default nation profile table into TSimMgr's parallel arrays.
  for (int row = 0; row < 7; ++row) {
    nationControlModes[row] = g_aDefaultNationSetupPolicyProfiles[row][0];
    cityMinisterPolicyIds[row] = g_aDefaultNationSetupPolicyProfiles[row][1];
    foreignMinisterPolicyIds[row] = g_aDefaultNationSetupPolicyProfiles[row][2];
    defenseMinisterPolicyIds[row] = g_aDefaultNationSetupPolicyProfiles[row][3];
  }

  multiplayerGameActive = 0;
  reloadPoliticalMapState = 0;
  scenarioMapIndexPlusOne = 0;
  multiplayerSessionRole = 0;
}

// SYNTHETIC: IMPERIALISM 0x0057bb50
// TSimMgr::`scalar deleting destructor'
TSimMgr::~TSimMgr() {}

// FUNCTION: IMPERIALISM 0x0057bbf0
void TSimMgr::InitializeTurnFlowStateDefaults() {
  economicTurn = 0;
  activeNationSlot = -1;
  field14 = 0;
  turnStateCode = 1;
  turnFlowStatusFlags = 0;
  field_64 = 0;
  phaseStateByDecade[0] = 0;
  // Ten bytes 0x6f..0x78 (phaseStateByDecade[1..9] + field78) are filled with 1 in one
  // pass (dword/dword/word stores in the original); field78 is then overwritten with 2.
  memset(&phaseStateByDecade[1], 0x01, sizeof(phaseStateByDecade));
  field79 = 1;
  field78 = 2;
  // Developer-cheat probe: stat a file literally named "Conan" in the working directory;
  // the original discards the result and clears the cheat flag unconditionally (the flag
  // is armed elsewhere).
  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = 0;
  ReinitializeRandomSeed();
  difficultyLevel = 0;
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
    g_pInterNationEventQueueManager->Free();
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

  TCountry** descriptorCursor = g_apTerrainTypeDescriptorTable;
  for (i = 0x17; i != 0; --i) {
    TCountry* descriptor = *descriptorCursor;
    if (descriptor != nullptr) {
      descriptor->Free();
      descriptor = nullptr;
    }
    *descriptorCursor = descriptor;
    ++descriptorCursor;
  }

  for (i = 0; i < 7; ++i) {
    g_apNationStates[i] = nullptr;
  }

  for (i = 0; i < 0x10; ++i) {
    g_apNationAuxRuntimeStateSlots[i] = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0057bea0
void TSimMgr::ReadFrom(TStream* stream) {
  int i;
  TObject::ReadFrom(stream);

  if (g_nSaveFormatVersion < 0x38) {
    short quarters;
    short years;
    stream->ReadBytes(&quarters, 2);
    stream->ReadBytes(&years, 2);
    economicTurn = quarters + years * 4;
  } else {
    stream->ReadBytes(&economicTurn, 2);
  }

  stream->ReadBytes(&activeNationSlot, 2);
  stream->ReadBytes(&turnStateCode, 2);
  stream->ReadBytes(&mode, 2);
  stream->ReadBytes(&previousTurnStateCode, 2);
  stream->ReadBytes(&previousMode, 2);
  stream->ReadBytes(&field14, 1);
  stream->ReadBytes(&numGreatPowers, 4);
  stream->ReadBytes(&numMinorCountries, 4);
  stream->ReadBytes(&turnFlowStatusFlags, 4);

  if (g_nSaveFormatVersion >= 0x20) {
    difficultyLevel = stream->ReadInteger() & 0xff;
  }

  if (g_nSaveFormatVersion < 0x2d) {
    stream->ReadBytes(&multiplayerGameActive, 0x3c);
    scenarioMapIndexPlusOne = 0;
  } else {
    stream->ReadBytes(&multiplayerGameActive, 0x3e);
  }

  if (g_nSaveFormatVersion < 0x2e) {
    field_64 = 0x2711;
  } else {
    stream->ReadBytes(&field_64, 4);
  }

  stream->ReadBytes(&field15, 0x17);

  int dummy;
  stream->ReadBytes(&dummy, 4);

  unsigned char hasGameFlowState = multiplayerSessionRole != 0;
  if (hasGameFlowState) {
    g_pGameFlowState->ReadFrom(stream);
  }

  if (g_nSaveFormatVersion >= 0x24) {
    stream->ReadBytes(&preferenceValues[10], 2);
  }

  if (g_nSaveFormatVersion > 0x33) {
    short selectedIndex;
    stream->ReadBytes(&selectedIndex, 2);
    field6a = selectedIndex;
    g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(selectedIndex);
  } else {
    field6a = (scenarioMapIndexPlusOne != 0) ? 1 : 0;
    g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(field6a);
  }

  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();

  if (g_nSaveFormatVersion >= 0x36) {
    stream->ReadBytes(&field6c, 2);
  }

  if (g_nSaveFormatVersion < 0x3b) {
    memset(phaseStateByDecade, 0x01, sizeof(phaseStateByDecade));
    field79 = 1;
    phaseStateByDecade[0] = 0;
    phaseStateByDecade[(field6c - 0x717) / 10] = 2;
  } else {
    stream->ReadBytes(phaseStateByDecade, 0xc);
  }

  for (i = 0; i < 0x17; ++i) {
    CString emptyString(g_szEmptyString);
    sharedTextSlots[i] = emptyString;
  }

  if (g_nSaveFormatVersion >= 0x3c) {
    for (i = 0; i < 0x17; ++i) {
      stream->streamSlot70(&sharedTextSlots[i], 0x20);
    }
  }

  g_pUiViewManager->OpenFilesFor(1);
  RebuildGlobalOrderManagersAndCapabilityState(0);
  RebuildMapContextAndGlobalMapState(0, nullptr, 0);
  RebuildNationStateSlotsAndAvailability(0);

  turnStateCode = 4;
  StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x0057c230
void TSimMgr::WriteTo(TStream* stream) {
  int i;
  TObject::WriteTo(stream);

  stream->WriteBytesSlot78(&economicTurn, 2);
  stream->WriteBytesSlot78(&activeNationSlot, 2);
  stream->WriteBytesSlot78(&turnStateCode, 2);
  stream->WriteBytesSlot78(&mode, 2);
  stream->WriteBytesSlot78(&previousTurnStateCode, 2);
  stream->WriteBytesSlot78(&previousMode, 2);
  stream->WriteBytesSlot78(&field14, 1);
  stream->WriteBytesSlot78(&numGreatPowers, 4);
  stream->WriteBytesSlot78(&numMinorCountries, 4);
  stream->WriteBytesSlot78(&turnFlowStatusFlags, 4);
  stream->streamSlot7c(static_cast<unsigned char>(difficultyLevel));
  stream->WriteBytesSlot78(&multiplayerGameActive, 0x3e);
  stream->WriteBytesSlot78(&field_64, 4);
  stream->WriteBytesSlot78(&field15, 0x17);
  stream->WriteBytesSlot78(&multiplayerSessionRole, 4);

  unsigned char hasGameFlowState = multiplayerSessionRole != 0;
  if (hasGameFlowState) {
    g_pGameFlowState->WriteTo(stream);
  }

  stream->WriteBytesSlot78(&preferenceValues[10], 2);
  stream->WriteBytesSlot78(&field6a, 2);
  stream->WriteBytesSlot78(&field6c, 2);
  stream->WriteBytesSlot78(phaseStateByDecade, 0xc);

  for (i = 0; i < 0x17; ++i) {
    stream->streamSlotAc(&sharedTextSlots[i]);
  }
}

// FUNCTION: IMPERIALISM 0x0057c390
void TSimMgr::RebuildNationStateSlotsNoOp() {}

// FUNCTION: IMPERIALISM 0x0057c3b0
void TSimMgr::RebuildGlobalOrderManagersAndCapabilityState(char flag) {
  int i;
  if (((flag != 0) && (g_bMultiplayerScenarioSetupActive == 0)) ||
      ((flag == 0) && (g_bMultiplayerScenarioSetupActive != 0))) {
    if (flag != 0) {
      for (i = 0; i < 7; ++i) {
        nationControlModes[i] = g_aDefaultNationSetupPolicyProfiles[i][0];
        cityMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][1];
        foreignMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][2];
        defenseMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][3];
      }
      multiplayerGameActive = 0;
      reloadPoliticalMapState = 0;
    }

    numGreatPowers = 0;
    multiplayerGameActive = (multiplayerSessionRole != 0) ? 1 : 0;
    for (i = 0; i < 7; ++i) {
      if (field15[i] != 0) {
        numGreatPowers++;
      }
    }

    numMinorCountries = 0;
    for (i = 7; i < 0x17; ++i) {
      if (field15[i] != 0) {
        numMinorCountries++;
      }
    }

    if (g_pUiAnimator != nullptr) {
      g_pUiAnimator->Free();
      g_pUiAnimator = nullptr;
    }
    TAnimator* animator = new TAnimator();
    animator->InitializeUiTransientObjectRegistry(0x7fffffff);
    animator->OrphanCallChain_C2_I13_004a0c00();
    g_pUiAnimator = animator;

    if (g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->Free();
      g_pDiplomacyTurnStateManager = nullptr;
    }
    TDiplomacyMgr* diplomacyManager = new TDiplomacyMgr();
    diplomacyManager->InitializeTDiplomacyTurnStateManagerDefaults();
    g_pDiplomacyTurnStateManager = diplomacyManager;

    if (g_pNationInteractionStateManager != nullptr) {
      g_pNationInteractionStateManager->Free();
      g_pNationInteractionStateManager = nullptr;
    }
    TTradeMgr* tradeManager = new TTradeMgr();
    tradeManager->InitializeNationInteractionStateManagerDefaults();
    g_pNationInteractionStateManager = tradeManager;

    if (g_pInterNationEventQueueManager != nullptr) {
      g_pInterNationEventQueueManager->Free();
      g_pInterNationEventQueueManager = nullptr;
    }
    TNewsMgr* newsManager = new TNewsMgr();
    newsManager->InitializeInterNationEventQueueManager();
    g_pInterNationEventQueueManager = newsManager;

    if (g_pMapContextActionManager != nullptr) {
      g_pMapContextActionManager->Free();
      g_pMapContextActionManager = nullptr;
    }
    TArmyMgr* armyManager = new TArmyMgr();
    armyManager->InitializeMapContextActionManager();
    g_pMapContextActionManager = armyManager;

    if (g_pSelectedCivilianOrderState != nullptr) {
      g_pSelectedCivilianOrderState->Free();
      g_pSelectedCivilianOrderState = nullptr;
    }
    TCivMgr* civilianManager = new TCivMgr();
    civilianManager->ICivMgr();
    g_pSelectedCivilianOrderState = civilianManager;

    if (g_pNavyOrderManager != nullptr) {
      g_pNavyOrderManager->Free();
    }
    g_pNavyOrderManager = new TNavyMgr();
    g_pNavyOrderManager->INavyMgr();

    if (g_pCityOrderCapabilityState != nullptr) {
      g_pCityOrderCapabilityState->Free();
    }
    g_pCityOrderCapabilityState = new TTechMgr();
    g_pCityOrderCapabilityState->InitializeCityOrderCapabilityStateDefaults();
  }
}

// FUNCTION: IMPERIALISM 0x0057c7c0
void TSimMgr::RebuildMapContextAndGlobalMapState(int arg1, const char* arg2, int arg3) {
  int i;
  if (g_bMultiplayerScenarioSetupActive == 0) {
    CString local_10;
    for (i = 0; i < 0x17; ++i) {
      SetSharedStringFromMappedFlavorTextWithLengthClamp(&local_10, i);
      sharedTextSlots[i] = local_10;
    }
  }

  char rebuildFlag = static_cast<char>(arg1);
  if (((rebuildFlag != 0) && (g_bMultiplayerScenarioSetupActive == 0)) ||
      ((rebuildFlag == 0) && (g_bMultiplayerScenarioSetupActive != 0))) {
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

    if (g_bMultiplayerScenarioSetupActive == 0) {
      g_pGlobalMapState->hexNeighborWrapHorizontally20 = static_cast<char>(arg3);
      g_pGlobalMapState->BuildOrLoadGlobalMapStateForSession(nullptr, const_cast<char*>(arg2));
    } else {
      g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057c9a0
unsigned char TSimMgr::RecreateActiveMapContextAndInitializeGlobalMapState(int scenarioIndex) {
  scenarioMapIndexPlusOne = static_cast<short>(scenarioIndex + 1);

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
  if (g_bMultiplayerScenarioSetupActive == 0) {
    short profileBySlot[8];
    g_pGlobalMapState->ChooseNationSetupProfilesForOpenSlots(profileBySlot);

    for (i = 0; i < 7; ++i) {
      int val = profileBySlot[i];
      cityMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][1];
      foreignMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][2];
      defenseMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][3];
    }
  }

  if (multiplayerSessionRole != 0) {
    for (i = 0; i < 7; ++i) {
      int activeSessionId = g_pGameFlowState->nationSessionIds[i];
      int activeNationId = TouchSessionActiveNationId();
      if (activeSessionId == activeNationId) {
        nationControlModes[i] = 1;
      } else if (multiplayerSessionRole == 2) {
        nationControlModes[i] = 4;
      } else {
        nationControlModes[i] = (activeSessionId != 0) ? 3 : 2;
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

  if (g_bMultiplayerScenarioSetupActive == 0) {
    g_pDiplomacyTurnStateManager->RebuildCivilianOrderCompatibilityMatrices();
    g_pUiRuntimeContext->RebuildMapTileNeighborHighlightPolygonsForAllTiles();
    g_pCityOrderCapabilityState->GenerateRandomCapabilityPrioritySlots();
    g_pGlobalMapState->GenerateProvinceNames();
    RegenerateAllMapActionContextStatusCodes();
    g_pInterNationEventQueueManager->QueueInterNationEventType11(999, 1, 1);
    g_pInterNationEventQueueManager->QueueInterNationEventType11(999, 2, 1);

    const char* tagText = g_pGlobalMapState->scenarioTagText1c;
    if (tagText[0] == '.') {
      CString path;
      path.Format(s_PictWvGobPathFormat_00698BF4, tagText[1] - '0');
      if (TryGetFileMetadataForPath(&path)) {
        g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(tagText[1] - '0');
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057cda0
void TSimMgr::RebuildPrimaryNationStateForSlot(int slotIndex, char activate) {
  short nationSlot = static_cast<short>(slotIndex);
  int nationIndex = nationSlot;

  if (g_apNationStates[nationIndex] != nullptr) {
    g_apNationStates[nationIndex]->Free();
  }
  g_apNationStates[nationIndex] = nullptr;
  g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;

  short setupMode = nationControlModes[nationIndex];
  if (setupMode == 1) {
    unsigned char useClientNation = multiplayerSessionRole == 2;
    if (useClientNation != 0) {
      TGreatPower* pTVar5 = (TGreatPower*)new TClientGreatPower();
      g_apNationStates[nationIndex] = pTVar5;
    } else {
      unsigned char useHostNation = multiplayerSessionRole == 1;
      if (useHostNation != 0) {
        TGreatPower* pTVar5 = (TGreatPower*)new THostGreatPower();
        g_apNationStates[nationIndex] = pTVar5;
      } else {
        TGreatPower* pTVar5 = new TGreatPower();
        g_apNationStates[nationIndex] = pTVar5;
      }
    }
    g_apNationStates[nationIndex]->InitializeNationStateRuntimeSubsystems(slotIndex, 1);
    g_apTerrainTypeDescriptorTable[nationIndex] = g_apNationStates[nationIndex];
    if (g_bMultiplayerScenarioSetupActive == 0) {
      activeNationSlot = nationSlot;
      g_pStrategicMapViewSystem->RefreshCityCapabilityUiHandlesForActiveNation();
    }
    if (g_bMultiplayerScenarioSetupActive == 0) {
      unsigned char suspendPrimaryEventQueue = multiplayerSessionRole != 0;
      if (suspendPrimaryEventQueue != 0) {
        g_pGameFlowState->processPrimaryEventQueue = 0;
      }
      if (activate != 0) {
        TGreatPower* nationState = g_apNationStates[nationIndex];
        TCity* city = nationState != nullptr ? nationState->city : nullptr;
        nationState->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      unsigned char resumePrimaryEventQueue = multiplayerSessionRole != 0;
      if (resumePrimaryEventQueue != 0) {
        g_pGameFlowState->processPrimaryEventQueue = 1;
      }
    }
  } else if (setupMode == 4) {
    TGreatPower* pTVar5 = (TGreatPower*)new TRemoteGreatPower();
    g_apNationStates[nationIndex] = pTVar5;
    pTVar5->InitializeNationStateRuntimeSubsystems(
        slotIndex, g_pGameFlowState->nationSessionIds[nationIndex] != 0);
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    {
      CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
      g_apTerrainTypeDescriptorTable[nationIndex]->SetNationDisplayNameAndLocalizationSlotRef(
          nationName);
    }
    {
      CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
      g_apTerrainTypeDescriptorTable[nationIndex]->identitySharedString1 = nationName;
    }

    if (activate != 0 && scenarioMapIndexPlusOne != 0) {
      TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
      pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
    }
  } else if (setupMode == 3) {
    TGreatPower* pTVar5 = (TGreatPower*)new TProxyGreatPower();
    pTVar5->InitializeNationStateRuntimeSubsystems(slotIndex, 1);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (g_bMultiplayerScenarioSetupActive == 0) {
      if (activate != 0) {
        TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(slotIndex, slotIndex, 0x100);
    }
    {
      CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
      g_apTerrainTypeDescriptorTable[nationIndex]->SetNationDisplayNameAndLocalizationSlotRef(
          nationName);
    }
    {
      CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
      g_apTerrainTypeDescriptorTable[nationIndex]->identitySharedString1 = nationName;
    }
  } else if (setupMode == 2) {
    // Real allocation is operator_new(0xb70) followed by TAutoGreatPower::TAutoGreatPower()
    // (ctor thunk 0x407a31 -> 0x4e6b50) -- this slot is genuinely a TAutoGreatPower, not a
    // bare TGreatPower (whose object size is 0x964, too small for the tail AI state block).
    TAutoGreatPower* pTVar5 = new TAutoGreatPower();
    pTVar5->InitializeNationMinisterSubsystemsByPolicyIds(
        slotIndex, 2, cityMinisterPolicyIds[nationIndex], foreignMinisterPolicyIds[nationIndex],
        defenseMinisterPolicyIds[nationIndex]);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (g_bMultiplayerScenarioSetupActive == 0) {
      if (activate != 0) {
        TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      pTVar5->QueueMapActionMissionsForPortZoneCandidates();
      pTVar5->AssignDisplayNamesToUnnamedMilitaryUnits();
    }
  } else {
    g_apNationStates[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;
  }

  if (nationSlot == activeNationSlot) {
    unsigned char useSessionDisplayName = multiplayerSessionRole != 0;
    if (useSessionDisplayName != 0) {
      {
        CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
        g_apTerrainTypeDescriptorTable[nationIndex]->SetNationDisplayNameAndLocalizationSlotRef(
            nationName);
      }
      {
        CString nationName(g_pGameFlowState->nationDisplayNameSlots[nationIndex]);
        g_apTerrainTypeDescriptorTable[nationIndex]->identitySharedString1 = nationName;
      }
    } else {
      {
        CString nationName(g_cstrCountryNameSettingValue006A4220);
        g_apTerrainTypeDescriptorTable[nationIndex]->SetNationDisplayNameAndLocalizationSlotRef(
            nationName);
      }
      {
        CString nationName(g_cstrCountryNameSettingValue006A4220);
        g_apTerrainTypeDescriptorTable[nationIndex]->identitySharedString1 = nationName;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057d520
void TSimMgr::RebuildSecondaryNationStateForSlot(int slotIndex) {
  short nationSlot = static_cast<short>(slotIndex);
  if (nationSlot < 7) {
    g_apSecondaryNationStateSlots[nationSlot] = nullptr;
    return;
  }

  int nationIndex = nationSlot;
  TMinor* minor = nullptr;
  if (nationIndex < numMinorCountries + 7 && multiplayerSessionRole == 2) {
    if (g_apSecondaryNationStateSlots[nationIndex] != nullptr) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;
    minor = new TRemoteMinor();
    minor->InitializeSecondaryNationStateAndSelectHomeTile(static_cast<NationSlot>(slotIndex));
  } else if (nationIndex < numMinorCountries + 7) {
    if (g_apSecondaryNationStateSlots[nationIndex] != nullptr) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;

    minor = new TMinor();
    minor->InitializeSecondaryNationStateAndSelectHomeTile(static_cast<NationSlot>(slotIndex));

    g_apSecondaryNationStateSlots[nationIndex] = minor;
    g_apTerrainTypeDescriptorTable[nationIndex] = minor;

    if (g_bMultiplayerScenarioSetupActive == 0) {
      minor->SeedInitialMilitaryAndNavyOrdersForOwnedRegions();

      short cityRecordIndex =
          g_pGlobalMapState->terrainStateTable[static_cast<short>(minor->homeTileIndex)]
              .cityRecordIndex;
      int remainingOrders = 2;
      do {
        TMilitaryUnit* order = new TMilitaryUnit();
        order->IMilitaryUnit(2, cityRecordIndex, slotIndex, 0);
        order->SetOrders(static_cast<UnitOrder>(2), -1);
        --remainingOrders;
      } while (remainingOrders != 0);

      minor->AssignDisplayNamesToUnnamedMilitaryUnits();
    }
    return;
  } else {
    if (g_apSecondaryNationStateSlots[nationIndex] != nullptr) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
  }

  g_apSecondaryNationStateSlots[nationIndex] = minor;
  g_apTerrainTypeDescriptorTable[nationIndex] = minor;
}

// FUNCTION: IMPERIALISM 0x0057d830
void TSimMgr::GetSeason(CString* destString) {
  short offset = economicTurn % 4;
  GetString(10000, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0057d870
void TSimMgr::SetDifficultyLevel(int difficulty) {
  signed char zeroFlag = 0;
  difficultyLevel = difficulty;
  if (difficulty != 0) {
    if (0 < difficulty && difficulty <= 4) {
      this->preferenceValues[10] = static_cast<short>(zeroFlag);
      return;
    }
  } else {
    zeroFlag = 1;
  }
  this->preferenceValues[10] = static_cast<short>(zeroFlag);
}

// FUNCTION: IMPERIALISM 0x0057d8b0
short TSimMgr::GetEconomicTurn() {
  return economicTurn;
}

// FUNCTION: IMPERIALISM 0x0057d8d0
void TSimMgr::SetGameSetupValues(GameSetup* setup) {
  for (int i = 0; i < 7; ++i) {
    nationControlModes[i] = setup->nationControlModes[i];
    cityMinisterPolicyIds[i] = setup->cityMinisterPolicyIds[i];
    foreignMinisterPolicyIds[i] = setup->foreignMinisterPolicyIds[i];
    defenseMinisterPolicyIds[i] = setup->defenseMinisterPolicyIds[i];
  }

  multiplayerGameActive = setup->multiplayerGameActive;
  if (setup->reloadPoliticalMapState != 0) {
    reloadPoliticalMapState = 1;
  }
}

// FUNCTION: IMPERIALISM 0x0057d950
void TSimMgr::AdvanceSeason() {
  ++economicTurn;
}

// FUNCTION: IMPERIALISM 0x0057d970
void TSimMgr::StartNextPhase() {
  g_pImperialismApp->PostStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x0057d990
void TSimMgr::EnterOptionalPhase(int gamePhase) {
  bool mayEnterPhase = IsNationEligibleForOptionalPhase(activeNationSlot);
  if (mayEnterPhase == false) {
    switch (gamePhase) {
    case 100:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6d:
      return;
    }
  }

  int oldPhase = this->turnStateCode;
  this->turnStateCode = gamePhase;
  this->previousMode = mode;
  previousTurnStateCode = oldPhase;
  StartNextPhase();
}

// TSimMgr::AdvanceGlobalTurnStateMachine (0x0057da70) is defined in its own translation unit,
// src/game/TSimMgr_AdvanceGlobalTurnStateMachine.cpp, so its large inline switch body does not
// perturb the codegen of the methods in this file.

// FUNCTION: IMPERIALISM 0x0057f110
int TSimMgr::InLinearPhase() {
  int phase = turnStateCode;
  return (phase <= 3) || (phase >= 6);
}

// FUNCTION: IMPERIALISM 0x0057f140
void TSimMgr::DoCityAndTransport() {
  int nationSlot = 6;
  TGreatPower** nation = &g_apNationStates[6];
  do {
    if (!IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      --nation;
      --nationSlot;
      continue;
    }
    bool shouldRunHandlers = !(*nation)->IsRemote();
    if (shouldRunHandlers) {
      (*nation)->FillInteriorMinisterOrders();
      (*nation)->NotifyCitySlot2C();
      (*nation)->ExecuteNationPendingActionStateMachine();
      (*nation)->RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary();
      (*nation)->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    }
    --nation;
    --nationSlot;
  } while (nation >= g_apNationStates);
}

// FUNCTION: IMPERIALISM 0x0057f200
void TSimMgr::DoCivilians() {
  g_pSelectedCivilianOrderState->ResolveCivilianDisputes();
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      g_apNationStates[nationSlot]->RunSlot4CThenSortTrackedOrders();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057f280
void TSimMgr::DoMilitary() {
  int isClient = multiplayerSessionRole == 2;
  if (!isClient) {
    g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  }

  for (int terrainSlot = 0; terrainSlot < kTerrainTypeDescriptorTableCount; ++terrainSlot) {
    if (IsNationEligibleForOptionalPhase(static_cast<short>(terrainSlot))) {
      g_apTerrainTypeDescriptorTable[terrainSlot]->QueueRecruitOrdersForUndergarrisonedRegions();
    }
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (!IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationSlot];
    nation->PayForMilitary();
    nation->SelectAndQueueAdvisoryMapMissionsCase16();
    nation->ResetField900FromNeedCapA6();
  }

  g_pMapContextActionManager->CleanUpStacks();
  isClient = multiplayerSessionRole == 2;
  if (!isClient) {
    g_pNavyOrderManager->PrepareToCarryOutAllOrders(1);
    g_pNavyOrderManager->CarryOutOrders();
  }
}

// FUNCTION: IMPERIALISM 0x0057f3c0
void TSimMgr::DoTrade() {
  g_pUiRuntimeContext->DispatchTurnEvent(0x2134, activeNationSlot);

  for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
    if (g_apNationStates[nationSlot] != 0) {
      g_apNationStates[nationSlot]->ReleaseDiplomacyTrackedObjectSlots850();
    }
  }

  g_pNationInteractionStateManager->ResetNationMetricRowsAndClearCategoryRankLists();
  g_pNationInteractionStateManager->RunNationUpdatePassesAndResetTransitionFlags();
  g_pNationInteractionStateManager->RunNationMetricPreUpdatePassAcrossSecondaryNations();
  g_pNationInteractionStateManager->BuildEligibleNationMetricBucketsAndWeightedTrendScores();
  g_pNationInteractionStateManager->DispatchNationMetricUpdatePassForAllSlots();
  g_pNationInteractionStateManager->AccumulateDiplomacyRelationChangesAndQueueEvents();

  int shouldSendTradeBook = multiplayerSessionRole != 0;
  if (shouldSendTradeBook) {
    g_pGameFlowState->SendTradeBook();
  }
  g_pNationInteractionStateManager->InitializePendingDiplomacyTransferCursorAndProcess();
}

// FUNCTION: IMPERIALISM 0x0057f490
int TSimMgr::PlayerLost() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057f4b0
void TSimMgr::SetFlags(unsigned int flags) {
  turnFlowStatusFlags |= flags;
}

// Out-of-line in the original: every callsite (ShowTurnAlertsForActiveNation x3,
// HandleTurnEvent7DD x8) calls this copy instead of inlining the mask test.
// FUNCTION: IMPERIALISM 0x0057f4d0
unsigned char TSimMgr::TestTurnFlowStatusFlagMask(unsigned int mask) {
  // test+setne needs the branchy if/return-1/return-0 shape (VC5 folds it to a byte
  // set); every value-form spelling (`!= 0`, bool, ternary) emits neg/sbb/neg instead.
  if (mask & turnFlowStatusFlags) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057f4f0
int TSimMgr::AllHumansFinished() {
  for (TGreatPower** nation = g_apNationStates; nation < &g_apNationStates_End; ++nation) {
    if ((*nation)->field904 == 0) {
      return 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0057f530
void TSimMgr::ResetTurnFlags() {
  TGreatPower** nation = g_apNationStates;
  do {
    if ((*nation)->diplomacyEligibilityA0 != 0) {
      (*nation)->field904 = 0;
    }
    ++nation;
  } while (nation < &g_apNationStates_End);
}

// FUNCTION: IMPERIALISM 0x0057f5b0
void TSimMgr::NumToCurrency(int value, CString* destString) {
  CString thousandsSep(",");

  int absValue = value;
  if (value < 0) {
    absValue = abs(value);
  }

  char* buf = destString->GetBuffer(0x11);
  _itoa(absValue, buf, 10);
  destString->ReleaseBuffer(-1);

  int len = destString->GetLength();
  if (len > 6) {
    CString last6 = destString->Right(6);
    CString firstRest = destString->Left(len - 6);
    *destString = firstRest + thousandsSep + last6;
  }
  if (len > 3) {
    CString last3 = destString->Right(3);
    CString firstRest = destString->Left(len - 3);
    *destString = firstRest + thousandsSep + last3;
  }
  *destString = '$' + *destString;
  if (value < 0) {
    *destString = '-' + *destString;
  }
}

// FUNCTION: IMPERIALISM 0x0057f8f0
void TSimMgr::NumToOrdinal(int value, CString* destString) {
  CString numberStr;
  numberStr.Format(g_szDecimalFormat, value);

  // English ordinal suffix selection (1st/2nd/3rd/Nth, with the 11/12/13 exceptions).
  int suffixCode;
  int remainder = value % 10;
  if (remainder == 1 && value != 11) {
    suffixCode = 0;
  } else if (remainder == 2 && value != 12) {
    suffixCode = 1;
  } else if (remainder == 3 && value != 13) {
    suffixCode = 2;
  } else {
    suffixCode = 3;
  }

  CString suffixTemplate;
  g_pSimMgr->GetString(0x275f, suffixCode, &suffixTemplate);
  scanBracketExpressions(this, destString, static_cast<LPCSTR>(suffixTemplate),
                         static_cast<LPCSTR>(numberStr));
}

// FUNCTION: IMPERIALISM 0x0057fe90
void TSimMgr::GetStringPrelude(short offset, CString* destString) {
  GetString(0x2711, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0057fec0
void TSimMgr::ReinitializeRandomSeed() {
#ifdef IMPERIALISM_RUNTIME_TESTS
  srand(RuntimeTestDriver::RandomSeed());
#else
  srand(static_cast<unsigned int>(time(0)));
#endif
}

// FUNCTION: IMPERIALISM 0x00580760
void TSimMgr::GetString(short codeGroup, short offset, CString* destString) {
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(destString, codeGroup,
                                                                  offset + 1);
}

// FUNCTION: IMPERIALISM 0x00580790
CString TSimMgr::DiplomacyNoticeString(const DiplomacyNotice* notice) {
  CString result;
  CString countryName;
  CString formattedValue;

  short code = notice->policyOrGrantCode;
  char rejected = 0;
  if (code < 0) {
    rejected = 1;
    code = static_cast<short>(-code);
  }

  g_apTerrainTypeDescriptorTable[notice->nationSlot]->FormatOverlayTerrainLabelText(&countryName);

  switch (code) {
  case 5:
  case 7:
  case 8:
  case 9:
  case 10:
  case 11:
  case 12: {
    CString commodityName;
    g_pSimMgr->GetStringPrelude(code, &commodityName);
    CString noticeText = "Shortage of " + commodityName + " in " + countryName + ".";
    result = noticeText;
    break;
  }
  case 0x12d:
    if (rejected) {
      CString noticeText = countryName + " has rejected our invitation to join our Empire!";
      result = noticeText;
    } else {
      CString noticeText =
          "Our power grows! " + countryName + " has accepted our invitation to join our Empire!";
      result = noticeText;
    }
    break;
  case 0x12e:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of an alliance";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of an alliance";
      result = noticeText;
    }
    break;
  case 0x12f:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of a non-aggression pact";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of a non-aggression pact";
      result = noticeText;
    }
    break;
  case 0x130:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of a peace treaty.";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of a peace treaty.";
      result = noticeText;
    }
    break;
  case 0x131: {
    CString noticeText = "War! " + countryName + "declares war on us!";
    result = noticeText;
    break;
  }
  case 1000:
  case 3000:
  case 5000:
  case 10000:
    g_pSimMgr->NumToCurrency(code, &formattedValue);
    {
      CString noticeText = countryName + " grants us " + formattedValue + ".";
      result = noticeText;
    }
    break;
  default:
    formattedValue.Format(g_szDecimalFormat, static_cast<int>(code));
    {
      CString noticeText =
          "TViewMgr::ShowDiplomacyNotices: " + countryName + " policy Num = " + formattedValue;
      result = noticeText;
    }
    break;
  }

  return result;
}

// FUNCTION: IMPERIALISM 0x005811e0
int TSimMgr::GetNumGPs(void) {
  return numGreatPowers;
}

// FUNCTION: IMPERIALISM 0x00581200
void TSimMgr::ReduceNumGPs() {
  --numGreatPowers;
}

// FUNCTION: IMPERIALISM 0x00581240
int TSimMgr::GetNumCountries() {
  return numMinorCountries + numGreatPowers;
}

// FUNCTION: IMPERIALISM 0x00581260
NationSlot TSimMgr::GetActiveNationId() {
  return activeNationSlot;
}

// FUNCTION: IMPERIALISM 0x00581280
char TSimMgr::IsNationSlotEligibleForEventProcessing(NationSlot nationSlot) {
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

// FUNCTION: IMPERIALISM 0x00581300
void TSimMgr::RemoveNationSlotAndNotifyPeers(NationSlot nationSlot) {
  // Neutralize the removed nation's diplomacy percent field on every other live slot. For
  // the seven great-power slots a nation whose terrain profile is in the reserved band
  // [100,200) is left alone; minor slots (i >= 7) and unreserved great powers are reset.
  TGreatPower** nationCursor = g_apNationStates;
  short i = 0;
  do {
    if (i != nationSlot && i != -1) {
      TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[i];
      if (terrainDescriptor != 0) {
        if (i >= 7 || terrainDescriptor->encodedNationSlot < 100 ||
            terrainDescriptor->encodedNationSlot >= 200) {
          (*nationCursor)->SetNationPercentFieldByModeAndDescriptorLinks(nationSlot, 500);
        }
      }
    }
    ++nationCursor;
    ++i;
  } while (nationCursor < &g_apNationStates[7]);

  if (g_apNationStates[nationSlot] != 0) {
    g_apNationStates[nationSlot]->Free();
  }
  g_apNationStates[nationSlot] = 0;
  g_apTerrainTypeDescriptorTable[nationSlot] = 0;
  field15[nationSlot] = 0;
  --numGreatPowers;
  g_pDiplomacyTurnStateManager->RemoveNationSlotAndNotifyPeers_Impl(nationSlot);
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

// FUNCTION: IMPERIALISM 0x00581510
void TSimMgr::UpdatePersistentTopTenNationScores() {
  CString path;
  CString ownNationName;
  GetString(0x2737, 0xd, &ownNationName);

  AssignScoresDatPathToSharedString(&path);
  FILE* file = fopen(path, "rb");

  int scoreValues[10];
  char scoreRecords[10][0x20];
  for (int i = 0; i < 10; ++i) {
    if (file != 0 && fread(&scoreValues[i], 4, 1, file) != 0) {
      fread(scoreRecords[i], 0x20, 1, file);
    } else {
      scoreValues[i] = 0;
      strcpy(scoreRecords[i], ownNationName);
    }
  }
  if (file != 0) {
    fclose(file);
  }

  g_apNationStates[activeNationSlot]->RecomputeNationEconomyAndDiplomacySummaryMetrics();
  int score = g_apNationStates[activeNationSlot]->economySummaryWeightedTotal95c;

  int insertIndex = 0;
  while (insertIndex < 10 && score <= scoreValues[insertIndex]) {
    ++insertIndex;
  }

  if (insertIndex < 10) {
    for (int j = 9; j > insertIndex; --j) {
      scoreValues[j] = scoreValues[j - 1];
      strcpy(scoreRecords[j], scoreRecords[j - 1]);
    }
    scoreValues[insertIndex] = score;

    CString recordName;
    g_apNationStates[activeNationSlot]->FormatOverlayTerrainLabelText(&recordName);
    strcpy(scoreRecords[insertIndex], recordName);

    FILE* writeFile = fopen(path, "wb");
    for (int i = 0; i < 10; ++i) {
      fwrite(&scoreValues[i], 4, 1, writeFile);
      fwrite(scoreRecords[i], 0x20, 1, writeFile);
    }
    fclose(writeFile);
  }
}

// The "Done/advance" turn-flow bootstrap primitive (free __cdecl in the TSimMgr TU): the
// single writer of g_bTurnFlowBootstrapComplete and the funnel every menu/score-screen advance routes
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
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGameFlowState->Free();
    g_pGameFlowState = new TMultiplayerMgr();
    g_pGameFlowState->InitializeMultiplayerManagerForSessionContext(0);
  }
  if (eventCode == 0x5dd) {
    TSimMgr* simMgr = g_pSimMgr;
    simMgr->economicTurn = 0;
    simMgr->activeNationSlot = -1;
    simMgr->field14 = 0;
    simMgr->turnStateCode = 1;
    simMgr->turnFlowStatusFlags = 0;
    simMgr->field_64 = 0;
    simMgr->phaseStateByDecade[0] = 0;
    memset(&simMgr->phaseStateByDecade[1], 0x01, sizeof(simMgr->phaseStateByDecade));
    simMgr->field79 = 1;
    simMgr->field78 = 2;
    CFileStatus conanFileStatus;
    CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
    g_bRandomMapDeveloperCheatFlag = 0;
    simMgr->ReinitializeRandomSeed();
    g_pSimMgr->turnStateCode = 3;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(static_cast<short>(eventCode));
  } else {
    g_pSimMgr->Free();
    g_pSimMgr = new TSimMgr();
    g_pSimMgr->InitializeTurnFlowStateDefaults();
    g_pSimMgr->StartNextPhase();
    if (eventCode != 0) {
      g_pGlobalUiRootController->PostTurnEventCodeMessage2420(static_cast<short>(eventCode));
    }
  }
  g_bTurnFlowBootstrapComplete = 1;
}

// FUNCTION: IMPERIALISM 0x00581ae0
void TSimMgr::SetSelectedIndex6AAndTriggerRefresh(short index) {
  field6a = index;
  g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(index);
  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();
}

// FUNCTION: IMPERIALISM 0x00581b20
CString TSimMgr::LoadNormalizedCredentialName(short slot) {
  CString name = g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&sharedTextSlots[slot]);
  return name;
}

// FUNCTION: IMPERIALISM 0x00581bc0
CString TSimMgr::AssignSharedStringFromIndexedSlot7C(short slot) {
  return sharedTextSlots[slot];
}

// FUNCTION: IMPERIALISM 0x00581c00
void TSimMgr::NameCapitals() {
  for (short nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0) {
      continue;
    }

    const short cityRecordIndex = static_cast<short>(country->GetHomeRegionCityRecordIndex());
    CString capitalNameTemplate;
    CString countryName = LoadNormalizedCredentialName(nationSlot);
    CString capitalName;
    GetString(0x272a, 0, &capitalNameTemplate);
    scanBracketExpressions(this, &capitalName, static_cast<LPCSTR>(capitalNameTemplate),
                           static_cast<LPCSTR>(countryName));
    g_pGlobalMapState->SetGlobalMapCellSharedLabel(cityRecordIndex, &capitalName);
  }
}

// FUNCTION: IMPERIALISM 0x00581e60
void TSimMgr::ProcessScenarioScript() {
  CString scenarioPath;
  gateFlag7a = 1;
  g_nSaveFormatVersion = -3;
  g_bScenarioScriptTerminationRequested = 0;
  g_nScenarioScriptInstructionCount = 0;

  g_pUiViewManager->BuildScenarioPathForModeAndIndex(
      static_cast<short>(scenarioMapIndexPlusOne) - 1, 2, &scenarioPath);

  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    CString ordinalText;
    ordinalText.Format(g_szDecimalFormat, zone->GetContextOrdinalOrInvalid());
    zone->displayName = ordinalText;
  }

  CFile_Virtuals* stream = g_pUiViewManager->LoadTableResourceStreamByName(scenarioPath);
  int resourceSize = g_pUiViewManager->GetResourceStreamSize(stream);
  unsigned char* buffer = new unsigned char[resourceSize];
  g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, buffer, &resourceSize);
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(stream);

  STurnInstructionCursor instruction;
  instruction.tokenCursor = reinterpret_cast<unsigned int*>(buffer);
  unsigned int instructionTag = 0;
  while (reinterpret_cast<unsigned char*>(instruction.tokenCursor) < buffer + resourceSize &&
         instructionTag != 0x5445524d && g_bScenarioScriptTerminationRequested == 0) {
    instructionTag = *instruction.tokenCursor;
    int instructionCount = g_nScenarioScriptInstructionCount;
    unsigned char* raw = reinterpret_cast<unsigned char*>(&instructionTag);
    unsigned char temp = raw[0];
    raw[0] = raw[3];
    raw[3] = temp;
    temp = raw[1];
    raw[1] = raw[2];
    raw[2] = temp;
    instruction.tokenCursor = instruction.tokenCursor + 1;
    ++instructionCount;
    g_nScenarioScriptInstructionCount = instructionCount;

    if (instructionTag != 0x5445524d) {
      int handlerIndex = 0;
      while (handlerIndex < 27 &&
             g_anScenarioScriptInstructionTags[handlerIndex] != instructionTag) {
        ++handlerIndex;
      }
      (this->*g_apfnScenarioScriptInstructionHandlers[handlerIndex])(&instruction);
    }
  }

  delete[] buffer;
  if (g_bScenarioScriptTerminationRequested != 0) {
    PostWmCloseToMainThreadWindow();
  }

  TGreatPower** nationCursor = g_apNationStates;
  while (nationCursor < &g_apNationStates_End) {
    (*nationCursor)->AssignDisplayNamesToUnnamedMilitaryUnits();
    (*nationCursor)->MarkStatusFlag5HandledIfCapabilityActive();
    ++nationCursor;
  }

  gateFlag7a = 0;
  g_nSaveFormatVersion = -1;
}

// Reads a big-endian 32-bit nation index and three big-endian 16-bit tokens (three labor
// tier counts). Applies them to the nation's city population summary (baseline/production
// tier buckets, need totals), kicks off a resource-yield rebuild, and notifies the nation's
// defense minister (if any) via its slot-0x14 hook.
// FUNCTION: IMPERIALISM 0x00582120
void TSimMgr::HandleTurnInstruction_Labo_SetNationLaborTierCounts(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* oraw = reinterpret_cast<unsigned char*>(&ownerToken);
  unsigned char ot = oraw[0];
  oraw[0] = oraw[3];
  oraw[3] = ot;
  ot = oraw[1];
  oraw[1] = oraw[2];
  oraw[2] = ot;

  unsigned int tierAToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* araw = reinterpret_cast<unsigned char*>(&tierAToken);
  araw[0] = araw[3];
  araw[1] = araw[2];

  unsigned int tierBToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* braw = reinterpret_cast<unsigned char*>(&tierBToken);
  braw[0] = braw[3];
  braw[1] = braw[2];

  unsigned int tierCToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* craw = reinterpret_cast<unsigned char*>(&tierCToken);
  craw[0] = craw[3];
  craw[1] = craw[2];

  TGreatPower* nation = g_apNationStates[ownerToken];
  TCity* city = (nation != nullptr) ? nation->city : nullptr;
  city->productionSummary1d8->SetPopulation(
      static_cast<int>(tierAToken), static_cast<int>(tierBToken), static_cast<int>(tierCToken));

  g_apNationStates[ownerToken]->RebuildNationResourceYieldCountersAndDevelopmentTargets();

  if (g_apNationStates[ownerToken]->interiorMinister != nullptr) {
    g_apNationStates[ownerToken]->interiorMinister->MinisterSlot14();
  }
}

// Reads a big-endian 32-bit nation slot, a big-endian short production-order index, and a
// big-endian short value; sets that nation's capital-city production-order slot to the
// value while accumulating the delta (value - old) into the parallel running-total slot.
// FUNCTION: IMPERIALISM 0x005822c0
void TSimMgr::HandleTurnInstruction_Capa_ApplyNationSlotValueWithDelta(void* pInstructionRaw) {
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

  unsigned int indexToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* iraw = reinterpret_cast<unsigned char*>(&indexToken);
  iraw[0] = iraw[3];
  iraw[1] = iraw[2];

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == nullptr) {
    city = nullptr;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  int index = static_cast<short>(indexToken);
  short value = static_cast<short>(valueToken);
  short* accum = &city->productionAccum1fc[index];
  *accum = static_cast<short>(*accum + (value - city->productionOrderTable1dc[index]));
  city->productionOrderTable1dc[index] = value;
}

// Reads a big-endian 32-bit nation slot, a big-endian short commodity index, and a
// big-endian short amount; writes the amount into that nation's capital-city commodity
// stock counter and re-verifies the city's stock invariants.
// FUNCTION: IMPERIALISM 0x005823e0
void TSimMgr::HandleTurnInstruction_Ware_ApplyNationIndexedShortAndRefresh(void* pInstructionRaw) {
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

  unsigned int indexToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* iraw = reinterpret_cast<unsigned char*>(&indexToken);
  iraw[0] = iraw[3];
  iraw[1] = iraw[2];

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == nullptr) {
    city = nullptr;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  (&city->cityStockCottonB6)[static_cast<short>(indexToken)] = static_cast<short>(valueToken);
  city->VerifyStocks();
}

// Reads a region index, a recruit-order type, and a repeat count. The region owner is
// taken from the map-state city-score row; each requested order is registered there and
// put into order mode 2 with the original -1 payload.
// FUNCTION: IMPERIALISM 0x005824c0
void TSimMgr::HandleTurnInstruction_Army_DeserializeAndCreateRecruitOrders(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int regionToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* regionRaw = reinterpret_cast<unsigned char*>(&regionToken);
  unsigned char temp = regionRaw[0];
  regionRaw[0] = regionRaw[3];
  regionRaw[3] = temp;
  temp = regionRaw[1];
  regionRaw[1] = regionRaw[2];
  regionRaw[2] = temp;

  unsigned int orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* orderTypeRaw = reinterpret_cast<unsigned char*>(&orderTypeToken);
  orderTypeRaw[0] = orderTypeRaw[3];
  orderTypeRaw[1] = orderTypeRaw[2];

  unsigned int countToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* countRaw = reinterpret_cast<unsigned char*>(&countToken);
  temp = countRaw[0];
  countRaw[0] = countRaw[3];
  countRaw[3] = temp;
  temp = countRaw[1];
  countRaw[1] = countRaw[2];
  countRaw[2] = temp;

  int remaining = static_cast<int>(countToken);
  int ownerNationCode =
      g_pGlobalMapState->cityScoreTable[static_cast<int>(regionToken)].ownerNationCode00;
  while (remaining > 0) {
    TMilitaryUnit* order = new TMilitaryUnit();
    order->IMilitaryUnit(static_cast<short>(orderTypeToken), static_cast<int>(regionToken),
                         ownerNationCode, 0);
    order->SetOrders(static_cast<UnitOrder>(2), -1);
    --remaining;
  }
}

// Reads a civilian work-order type and terrain row, resolves the row's owner tag, then
// constructs and registers the corresponding civilian order. The dispatch receiver is
// TSimMgr; the previous TGreatPower ownership was a Ghidra-attribution error.
// FUNCTION: IMPERIALISM 0x00582630
void TSimMgr::HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* orderTypeRaw = reinterpret_cast<unsigned char*>(&orderTypeToken);
  orderTypeRaw[0] = orderTypeRaw[3];
  orderTypeRaw[1] = orderTypeRaw[2];

  unsigned int terrainToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* terrainRaw = reinterpret_cast<unsigned char*>(&terrainToken);
  terrainRaw[0] = terrainRaw[3];
  terrainRaw[1] = terrainRaw[2];

  int ownerNationTag =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(terrainToken)].ownerNationTag04;
  TCivUnit* order = new TCivUnit();
  order->ICivUnit(static_cast<CivilianUnitKind>(orderTypeToken), terrainToken, ownerNationTag);
}

// Reads nation, navy-order type, map-action-context id, and count. It updates the
// nation's parallel city count then creates that many primary navy-order nodes.
// FUNCTION: IMPERIALISM 0x00582720
void TSimMgr::HandleTurnInstruction_Ship_DeserializeAndCreatePrimaryOrders(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int nationToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* nationRaw = reinterpret_cast<unsigned char*>(&nationToken);
  unsigned char temp = nationRaw[0];
  nationRaw[0] = nationRaw[3];
  nationRaw[3] = temp;
  temp = nationRaw[1];
  nationRaw[1] = nationRaw[2];
  nationRaw[2] = temp;

  unsigned int orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* orderTypeRaw = reinterpret_cast<unsigned char*>(&orderTypeToken);
  orderTypeRaw[0] = orderTypeRaw[3];
  orderTypeRaw[1] = orderTypeRaw[2];

  unsigned int contextToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* contextRaw = reinterpret_cast<unsigned char*>(&contextToken);
  contextRaw[0] = contextRaw[3];
  contextRaw[1] = contextRaw[2];

  unsigned int countToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* countRaw = reinterpret_cast<unsigned char*>(&countToken);
  temp = countRaw[0];
  countRaw[0] = countRaw[3];
  countRaw[3] = temp;
  temp = countRaw[1];
  countRaw[1] = countRaw[2];
  countRaw[2] = temp;

  short orderType = static_cast<short>(orderTypeToken);
  int nationSlot = static_cast<int>(nationToken);
  TZone* context = FindMapActionContextByNodeId(static_cast<short>(contextToken));
  TCity* city;
  if (g_apNationStates[nationSlot] == 0) {
    city = 0;
  } else {
    city = g_apNationStates[nationSlot]->city;
  }
  city->orderCountByType5c[orderType] =
      static_cast<short>(city->orderCountByType5c[orderType] + static_cast<short>(countToken));

  int remaining = static_cast<int>(countToken);
  while (remaining != 0) {
    CreateNavyPrimaryOrderNodeAndAssignDisplayName(orderType, context, nationSlot, 0);
    --remaining;
  }
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

// Reads a big-endian short tile index and a development value byte, then sets that tile's
// civilian development-class nibble -- selecting the high nibble only when the tile's
// resource/edge byte is one of the qualifying terrain codes.
// FUNCTION: IMPERIALISM 0x005828f0
void TSimMgr::HandleTurnInstruction_Deve_ApplyMapDevelopmentEntry(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int tileToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&tileToken);
  traw[0] = traw[3];
  traw[1] = traw[2];
  short tileIndex = static_cast<short>(tileToken);

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;

  int terrainCode = g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[0];
  char selectHighNibble = 0;
  if (terrainCode == 0x16 || terrainCode == 0x15 || terrainCode == 0x04 || terrainCode == 0x03 ||
      terrainCode == 0x06) {
    selectHighNibble = 1;
  }
  unsigned char value = reinterpret_cast<unsigned char*>(&valueToken)[3];
  g_pGlobalMapState->SetCivilianDevelopmentClassNibble(tileIndex, selectHighNibble, value, 1);
}

// Reads one big-endian short tile index, resolves that tile's owner nation, queues a depot
// construction order there, and grants the owner a 2000 cash bonus when it is not
// diplomacy-eligible.
// FUNCTION: IMPERIALISM 0x005829b0
void TSimMgr::HandleTurnInstruction_Rail_ApplyRailPlacementAndCashBonus(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token = *cursor;
  instruction->tokenCursor = cursor + 1;
  unsigned char* raw = reinterpret_cast<unsigned char*>(&token);
  raw[0] = raw[3];
  raw[1] = raw[2];
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  g_pGlobalMapState->QueueDepotConstructionOrder(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibilityA0 == 0) {
    g_apNationStates[nationTag]->treasuryValue10 += 2000;
  }
}

// Reads one big-endian short tile index, resolves that tile's owner nation, queues a port
// construction order there, and grants the owner a 3000 cash bonus when it is not
// diplomacy-eligible.
// FUNCTION: IMPERIALISM 0x00582a40
void TSimMgr::HandleTurnInstruction_Port_ApplyPortPlacementAndCashBonus(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token = *cursor;
  instruction->tokenCursor = cursor + 1;
  unsigned char* raw = reinterpret_cast<unsigned char*>(&token);
  raw[0] = raw[3];
  raw[1] = raw[2];
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  g_pGlobalMapState->QueuePortConstructionOrder(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibilityA0 == 0) {
    g_apNationStates[nationTag]->treasuryValue10 += 3000;
  }
}

// Reads two big-endian 32-bit tokens (forced nation slot, then tech id) and applies the
// tech unlock via the city-order capability state singleton.
// FUNCTION: IMPERIALISM 0x00582ad0
void TSimMgr::HandleTurnInstruction_Tech_ApplyTechUnlockAndNotifyNations(void* pInstructionRaw) {
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

  unsigned int techToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&techToken);
  unsigned char tt = traw[0];
  traw[0] = traw[3];
  traw[3] = tt;
  tt = traw[1];
  traw[1] = traw[2];
  traw[2] = tt;

  g_pCityOrderCapabilityState->ApplyTechUnlockAndQueueNationAbilityNotices(
      static_cast<int>(techToken), static_cast<int>(nationToken));
}

// Reads two big-endian 16-bit tokens (metric category, then value) and applies the value
// via the trade manager's per-nation metric cell setter.
// FUNCTION: IMPERIALISM 0x00582b70
void TSimMgr::HandleTurnInstruction_Pric_ApplyDiplomacyPriceEntry(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int categoryToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* craw = reinterpret_cast<unsigned char*>(&categoryToken);
  craw[0] = craw[3];
  craw[1] = craw[2];

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  g_pNationInteractionStateManager->SetNationMetricCellValueByIndex(
      static_cast<short>(categoryToken), static_cast<short>(valueToken));
}

// Reads two big-endian 32-bit nation slots and a big-endian short relation value, then
// writes the value symmetrically into both [A][B] and [B][A] of the diplomacy manager's
// side-effect relation matrix.
// FUNCTION: IMPERIALISM 0x00582bf0
void TSimMgr::HandleTurnInstruction_Emba_SetEmbassyRelationFlags(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationAToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* araw = reinterpret_cast<unsigned char*>(&nationAToken);
  unsigned char at = araw[0];
  araw[0] = araw[3];
  araw[3] = at;
  at = araw[1];
  araw[1] = araw[2];
  araw[2] = at;

  unsigned int nationBToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* braw = reinterpret_cast<unsigned char*>(&nationBToken);
  unsigned char bt = braw[0];
  braw[0] = braw[3];
  braw[3] = bt;
  bt = braw[1];
  braw[1] = braw[2];
  braw[2] = bt;

  unsigned int valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  int nationA = static_cast<int>(nationAToken);
  int nationB = static_cast<int>(nationBToken);
  short value = static_cast<short>(valueToken);
  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  diplomacy->relationSideEffectMatrix1402[nationA * 0x17 + nationB] = value;
  diplomacy->relationSideEffectMatrix1402[nationB * 0x17 + nationA] = value;
}

// Reads a big-endian 32-bit owner-nation index plus two big-endian 16-bit tokens (target
// nation slot, then reset level) and applies them via the owner's diplomacy-level resetter.
// FUNCTION: IMPERIALISM 0x00582ce0
void TSimMgr::HandleTurnInstruction_Subs_ApplyNationSubsidyEntry(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* oraw = reinterpret_cast<unsigned char*>(&ownerToken);
  unsigned char ot = oraw[0];
  oraw[0] = oraw[3];
  oraw[3] = ot;
  ot = oraw[1];
  oraw[1] = oraw[2];
  oraw[2] = ot;

  unsigned int targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&targetToken);
  traw[0] = traw[3];
  traw[1] = traw[2];

  unsigned int levelToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* lraw = reinterpret_cast<unsigned char*>(&levelToken);
  lraw[0] = lraw[3];
  lraw[1] = lraw[2];

  g_apNationStates[ownerToken]->SetTradePolicyTo(static_cast<NationSlot>(targetToken),
                                                 static_cast<int>(levelToken));
}

// Reads source nation, target nation, and relation code, applies the diplomacy entry,
// and performs the symmetric relation-side-effect update used by code 5.
// FUNCTION: IMPERIALISM 0x00582da0
void TSimMgr::HandleTurnInstruction_Trea_ApplyTreatyAndRelationEntry(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int sourceToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* sourceRaw = reinterpret_cast<unsigned char*>(&sourceToken);
  unsigned char temp = sourceRaw[0];
  sourceRaw[0] = sourceRaw[3];
  sourceRaw[3] = temp;
  temp = sourceRaw[1];
  sourceRaw[1] = sourceRaw[2];
  sourceRaw[2] = temp;

  unsigned int targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* targetRaw = reinterpret_cast<unsigned char*>(&targetToken);
  temp = targetRaw[0];
  targetRaw[0] = targetRaw[3];
  targetRaw[3] = temp;
  temp = targetRaw[1];
  targetRaw[1] = targetRaw[2];
  targetRaw[2] = temp;

  unsigned int relationToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* relationRaw = reinterpret_cast<unsigned char*>(&relationToken);
  temp = relationRaw[0];
  relationRaw[0] = relationRaw[3];
  relationRaw[3] = temp;
  temp = relationRaw[1];
  relationRaw[1] = relationRaw[2];
  relationRaw[2] = temp;

  int sourceNation = static_cast<int>(sourceToken);
  int targetNation = static_cast<int>(targetToken);
  int relationCode = static_cast<int>(relationToken);
  g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(sourceNation, targetNation,
                                                                        relationCode);
  if (relationCode == 5) {
    TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
    short relationSideEffect = 2;
    diplomacy->relationSideEffectMatrix1402[sourceNation * kNationSlotCount + targetNation] =
        relationSideEffect;
    diplomacy->relationSideEffectMatrix1402[targetNation * kNationSlotCount + sourceNation] =
        relationSideEffect;
    g_apTerrainTypeDescriptorTable[targetNation]->ApplyJoinEmpireMode1TargetTransition(
        sourceNation);
  }
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
  economicTurn = static_cast<short>(token) * 4;
}

// Reads a big-endian short city-record index and a big-endian nation tag, then dispatches
// the province formation-entry action on the global map state.
// FUNCTION: IMPERIALISM 0x00582f20
void TSimMgr::HandleTurnInstruction_Prov_ApplyProvinceAssignmentEntry(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int cityToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* craw = reinterpret_cast<unsigned char*>(&cityToken);
  craw[0] = craw[3];
  craw[1] = craw[2];

  unsigned int nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* nraw = reinterpret_cast<unsigned char*>(&nationToken);
  nraw[0] = nraw[3];
  nraw[1] = nraw[2];

  g_pGlobalMapState->DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
      static_cast<short>(cityToken), static_cast<int>(nationToken));
}

// Reads a map-action-context id and a fixed 64-byte inline name, then updates the
// matching context's display name.
// FUNCTION: IMPERIALISM 0x00582fa0
void TSimMgr::HandleTurnInstruction_Zone_AssignMapActionContextNameByNodeId(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int contextToken = *instruction->tokenCursor;
  const char* rawName = reinterpret_cast<const char*>(instruction->tokenCursor + 1);
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* contextRaw = reinterpret_cast<unsigned char*>(&contextToken);
  contextRaw[0] = contextRaw[3];
  contextRaw[1] = contextRaw[2];

  CString contextName(rawName);
  instruction->tokenCursor =
      reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(instruction->tokenCursor) + 0x40);
  short contextId = static_cast<short>(contextToken);
  if (FindMapActionContextByNodeId(contextId) != 0) {
    TZone* context = FindMapActionContextByNodeId(contextId);
    context->displayName = contextName;
  }
}

// Reads a country slot and fixed 64-byte inline display name. The three otherwise-empty
// CString locals are present in the original body and are kept so VC5 emits the same EH
// construction/destruction shape.
// FUNCTION: IMPERIALISM 0x00583070
void TSimMgr::HandleTurnInstruction_Cnam_AssignCountryName(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int countryToken = *instruction->tokenCursor;
  const char* rawName = reinterpret_cast<const char*>(instruction->tokenCursor + 1);
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* countryRaw = reinterpret_cast<unsigned char*>(&countryToken);
  unsigned char temp = countryRaw[0];
  countryRaw[0] = countryRaw[3];
  countryRaw[3] = temp;
  temp = countryRaw[1];
  countryRaw[1] = countryRaw[2];
  countryRaw[2] = temp;

  CString countryName(rawName);
  instruction->tokenCursor =
      reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(instruction->tokenCursor) + 0x40);
  CString unusedNamePartA;
  CString unusedNamePartB;
  CString unusedNamePartC;

  int countryIndex = static_cast<int>(countryToken);
  g_apTerrainTypeDescriptorTable[countryIndex]->SetNationDisplayNameAndLocalizationSlotRef(
      countryName);
  g_apTerrainTypeDescriptorTable[countryIndex]->identitySharedString1 = countryName;
}

// Reads three big-endian 16-bit tokens (source nation, target nation, then relation
// score) and applies them via the diplomacy manager's standing-score setter.
// FUNCTION: IMPERIALISM 0x005831d0
void TSimMgr::HandleTurnInstruction_Rela_SetNationRelationValue(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int sourceToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* sraw = reinterpret_cast<unsigned char*>(&sourceToken);
  sraw[0] = sraw[3];
  sraw[1] = sraw[2];

  unsigned int targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&targetToken);
  traw[0] = traw[3];
  traw[1] = traw[2];

  unsigned int scoreToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&scoreToken);
  vraw[0] = vraw[3];
  vraw[1] = vraw[2];

  g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(
      static_cast<int>(sourceToken), static_cast<int>(targetToken), static_cast<int>(scoreToken));
}

// Reads a big-endian 32-bit tile-index token followed by a fixed 64-byte inline C-string
// (the province name) and applies it via the global map state's shared-label setter.
// FUNCTION: IMPERIALISM 0x00583270
void TSimMgr::HandleTurnInstruction_Pnam_AssignProvinceName(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int tileToken = *instruction->tokenCursor;
  const char* rawName = reinterpret_cast<const char*>(instruction->tokenCursor + 1);
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&tileToken);
  unsigned char tt = traw[0];
  traw[0] = traw[3];
  traw[3] = tt;
  tt = traw[1];
  traw[1] = traw[2];
  traw[2] = tt;

  CString rawText(rawName);
  instruction->tokenCursor =
      reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(instruction->tokenCursor) + 0x40);
  CString name(rawText);
  g_pGlobalMapState->SetGlobalMapCellSharedLabel(static_cast<int>(tileToken), &name);
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
  g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(index);
  g_pStrategicMapViewSystem->ReloadBitmap244AndRefreshUiCaches();
}

// Reads two big-endian 32-bit tokens (priority-slot index, then value) and applies the
// value (offset by 1) via the city-order capability state's tier setter.
// FUNCTION: IMPERIALISM 0x00583470
void TSimMgr::HandleTurnInstruction_Tyer_SetCityOrderCapabilityTierValue(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int indexToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* iraw = reinterpret_cast<unsigned char*>(&indexToken);
  unsigned char it = iraw[0];
  iraw[0] = iraw[3];
  iraw[3] = it;
  it = iraw[1];
  iraw[1] = iraw[2];
  iraw[2] = it;

  unsigned int valueToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  unsigned char vt = vraw[0];
  vraw[0] = vraw[3];
  vraw[3] = vt;
  vt = vraw[1];
  vraw[1] = vraw[2];
  vraw[2] = vt;

  g_pCityOrderCapabilityState->SetCityOrderCapabilityTierScaledValueByIndex(
      static_cast<int>(indexToken), static_cast<int>(valueToken + 1));
}

// Reads a big-endian 32-bit owner-nation index and two more big-endian 32-bit tokens (a
// relation-bar type selector, then a value). If the nation's current need for that type is
// below the value, kicks off a resource-yield rebuild; type 0/0x14 first remaps to a fixed
// need slot (1 or 0x13) and tops that need up to its current value before the value used
// below is replaced by the (now-capped) current reading; finally applies the value (needIndex
// = the type selector, or the capped current reading for the 0/0x14 case) via the need
// target/over-cap accumulator.
// FUNCTION: IMPERIALISM 0x00583510
void TSimMgr::HandleTurnInstruction_Tbar_SetNationRelationBarValue(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);

  unsigned int ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* oraw = reinterpret_cast<unsigned char*>(&ownerToken);
  unsigned char ot = oraw[0];
  oraw[0] = oraw[3];
  oraw[3] = ot;
  ot = oraw[1];
  oraw[1] = oraw[2];
  oraw[2] = ot;

  unsigned int typeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* traw = reinterpret_cast<unsigned char*>(&typeToken);
  unsigned char tt = traw[0];
  traw[0] = traw[3];
  traw[3] = tt;
  tt = traw[1];
  traw[1] = traw[2];
  traw[2] = tt;

  unsigned int valueToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&valueToken);
  unsigned char vt = vraw[0];
  vraw[0] = vraw[3];
  vraw[3] = vt;
  vt = vraw[1];
  vraw[1] = vraw[2];
  vraw[2] = vt;

  short needIndex = static_cast<short>(typeToken);
  int value = static_cast<int>(valueToken);

  if (g_apNationStates[ownerToken]->needCurrentByType[needIndex] < value) {
    g_apNationStates[ownerToken]->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  }

  if (typeToken == 0 || typeToken == 0x14) {
    short mappedIndex = (typeToken != 0) ? 0x13 : 1;
    unsigned short currentRaw = g_apNationStates[ownerToken]->needCurrentByType[needIndex];
    if (static_cast<short>(currentRaw) < value) {
      g_apNationStates[ownerToken]->UpdateNeedTargetAndAccumulateOverCap(
          mappedIndex, static_cast<short>(value - currentRaw));
      value = static_cast<short>(currentRaw);
    }
  }

  g_apNationStates[ownerToken]->UpdateNeedTargetAndAccumulateOverCap(needIndex,
                                                                     static_cast<short>(value));
}

// Reads a big-endian 32-bit nation slot, then rebuilds that nation's resource-yield /
// development targets and clears all 0x17 need targets back to zero.
// FUNCTION: IMPERIALISM 0x00583670
void TSimMgr::HandleTurnInstruction_Tclr_ResetNationRelationBars(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int nationToken = *cursor;
  instruction->tokenCursor = cursor + 1;
  unsigned char* nraw = reinterpret_cast<unsigned char*>(&nationToken);
  unsigned char nt = nraw[0];
  nraw[0] = nraw[3];
  nraw[3] = nt;
  nt = nraw[1];
  nraw[1] = nraw[2];
  nraw[2] = nt;
  int nation = static_cast<int>(nationToken);

  g_apNationStates[nation]->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  int needIndex = 0;
  do {
    g_apNationStates[nation]->UpdateNeedTargetAndAccumulateOverCap(static_cast<short>(needIndex),
                                                                   0);
    ++needIndex;
  } while (needIndex < 0x17);
}

// Reads a big-endian 32-bit country slot and a big-endian 32-bit state code. Stores the
// state's low byte into phaseStateByDecade, and when the state is
// exactly 2 latches field6c to slot*10 + 0x717.
// FUNCTION: IMPERIALISM 0x00583700
void TSimMgr::HandleTurnInstruction_Coun_SetCountrySlotState(void* pInstructionRaw) {
  STurnInstructionCursor* instruction = static_cast<STurnInstructionCursor*>(pInstructionRaw);
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int slotToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* sraw = reinterpret_cast<unsigned char*>(&slotToken);
  unsigned char st = sraw[0];
  sraw[0] = sraw[3];
  sraw[3] = st;
  st = sraw[1];
  sraw[1] = sraw[2];
  sraw[2] = st;

  unsigned int stateToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  unsigned char* vraw = reinterpret_cast<unsigned char*>(&stateToken);
  unsigned char vt = vraw[0];
  vraw[0] = vraw[3];
  vraw[3] = vt;
  vt = vraw[1];
  vraw[1] = vraw[2];
  vraw[2] = vt;

  int slot = static_cast<int>(slotToken);
  phaseStateByDecade[slot] = static_cast<unsigned char>(stateToken);
  if (stateToken == 2) {
    field6c = static_cast<short>(static_cast<short>(slotToken) * 10 + 0x717);
  }
}

// FUNCTION: IMPERIALISM 0x005837c0
void TSimMgr::SetActiveNationSlotAndRefreshCityCapabilityUiHandles(NationSlot nationSlot) {
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
