#include "game/nation_domain_types.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/assets/TCdAudioDevice.h"
#include "game/military_ui/TNextDiplomationCommand.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_screens.h"
#include "game/resource_domain_types.h"
#include "game/core/runtime_prng_seed.h"
#include "game/ui_screens/TSimMgr.h"

#include <cstring>
#include <stdio.h>
#include <stdlib.h>

#include "decomp_types.h"
#include "game/ImperialismApp.h"
#include "game/ui_core/TApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/gfx/TResourceMgr.h"
#include "game/navy_order.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/navy/TOcean.h"
#include "game/map/TMapMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TCivUnit.h"
#include "game/TTurnInstructionCursor.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/net/TNetMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/nation/TMinor.h"
#include "game/military/TMilitaryUnit.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/military/TRemoteGreatPower.h"
#include "game/military/TProxyGreatPower.h"
#include "game/military/TClientGreatPower.h"
#include "game/military/THostGreatPower.h"
#include "game/military/TRemoteMinor.h"
#include "game/app/TAnimator.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/military/mapped_flavor_text.h"

// LAYOUT: The turn and active-nation fields are words; the following counters are dwords.
ASSERT_OFFSET(TSimMgr, economicTurn, 0x2c);
ASSERT_OFFSET(TSimMgr, activeNationSlot, 0x2e);
ASSERT_OFFSET(TSimMgr, numGreatPowers, 0x30);
ASSERT_OFFSET(TSimMgr, numMinorCountries, 0x34);
ASSERT_OFFSET(TSimMgr, turnFlowStatusFlags, 0x3c);

#define DECODE_SCENARIO_DWORD_TOKEN(token)                                                         \
  unsigned char* token##Bytes = static_cast<unsigned char*>(static_cast<void*>(&token));           \
  unsigned char token##SwapByte = token##Bytes[0];                                                 \
  token##Bytes[0] = token##Bytes[3];                                                               \
  token##Bytes[3] = token##SwapByte;                                                               \
  token##SwapByte = token##Bytes[1];                                                               \
  token##Bytes[1] = token##Bytes[2];                                                               \
  token##Bytes[2] = token##SwapByte

#define DECODE_SCENARIO_SHORT_TOKEN(token)                                                         \
  unsigned char* token##Bytes = static_cast<unsigned char*>(static_cast<void*>(&token));           \
  token##Bytes[0] = token##Bytes[3];                                                               \
  token##Bytes[1] = token##Bytes[2]

static bool IsNationEligibleForOptionalPhase(short nationSlot) {
  if (nationSlot == -1) {
    return false;
  }
  TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
  if (country == NULL) {
    return false;
  }
  if (nationSlot >= kMajorNationCount) {
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
  return g_pNetMgr->GetPlayerID();
}

// FUNCTION: IMPERIALISM 0x005621b0
void __cdecl ResetPortZoneGlobalContextCounters(void) {
  g_nMapActionContextCount = 0;
  g_nMapActionContextDistanceCacheSizedFor = -1;
}

IMPLEMENT_DYNCREATE(TSimMgr, TObject)

// FUNCTION: IMPERIALISM 0x0057b9e0
TSimMgr::TSimMgr() : sharedTextSlots() {
  turnStateCode = kGamePhaseStartup;
  mode = kGamePhaseStartup;
  previousTurnStateCode = kGamePhaseStartup;
  previousMode = kGamePhaseStartup;
  field14 = 0;

  for (int i = 0; i < 0x17; ++i) {
    countryAvailable[i] = true;
    CString empty(g_szEmptyString);
    sharedTextSlots[i] = empty;
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
  reloadPoliticalMapState = false;
  scenarioMapIndexPlusOne = 0;
  multiplayerSessionRole = kSessionRoleStandalone;
}

// FUNCTION: IMPERIALISM 0x0057bb80
TSimMgr::~TSimMgr() {}

// FUNCTION: IMPERIALISM 0x0057bbf0
void TSimMgr::ISimMgr() {
  economicTurn = 0;
  activeNationSlot = -1;
  field14 = 0;
  turnStateCode = kGamePhaseStartup;
  turnFlowStatusFlags = 0;
  lastPersistentUnitId = 0;
  councilByDecade[0] = 0;
  memset(&councilByDecade[1], 0x01, sizeof(councilByDecade) - 1);
  councilByDecade[10] = 2;
  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = false;
  ReinitializeRandomSeed();
  difficultyLevel = kDifficultyIntroductory;
  UpdatePreferences(false);
  mapArtSet = 0;
  finalCouncilYear = 0x77a;
  newsEventsSuppressed = false;
}

// FUNCTION: IMPERIALISM 0x0057bc90
void TSimMgr::ResetTurnFlowStateAndRandomSeed() {
  economicTurn = 0;
  activeNationSlot = -1;
  field14 = 0;
  turnStateCode = kGamePhaseStartup;
  turnFlowStatusFlags = 0;
  lastPersistentUnitId = 0;
  councilByDecade[0] = 0;
  memset(&councilByDecade[1], 0x01, sizeof(councilByDecade) - 1);
  councilByDecade[10] = 2;

  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = false;
  ReinitializeRandomSeed();
}

// FUNCTION: IMPERIALISM 0x0057bd20
void TSimMgr::Free() {
  int i;
  if (g_pTradeMgr != NULL) {
    g_pTradeMgr->Free();
    g_pTradeMgr = NULL;
  }
  if (g_pDiplomacyTurnStateManager != NULL) {
    g_pDiplomacyTurnStateManager->Free();
    g_pDiplomacyTurnStateManager = NULL;
  }
  if (g_pMapContextActionManager != NULL) {
    g_pMapContextActionManager->Free();
    g_pMapContextActionManager = NULL;
  }
  if (g_pActiveMapOrderContext != NULL) {
    g_pActiveMapOrderContext->Free();
    g_pActiveMapOrderContext = NULL;
  }
  if (g_pGlobalMapState != NULL) {
    g_pGlobalMapState->Free();
    g_pGlobalMapState = NULL;
  }
  if (g_pTechMgr != NULL) {
    g_pTechMgr->Free();
    g_pTechMgr = NULL;
  }
  if (g_pNewsMgr != NULL) {
    g_pNewsMgr->Free();
    g_pNewsMgr = NULL;
  }
  if (g_pSelectedCivilianOrderState != NULL) {
    g_pSelectedCivilianOrderState->Free();
    g_pSelectedCivilianOrderState = NULL;
  }
  if (g_pUiAnimator != NULL) {
    g_pUiAnimator->Free();
    g_pUiAnimator = NULL;
  }
  if (g_pNavyOrderManager != NULL) {
    g_pNavyOrderManager->Free();
    g_pNavyOrderManager = NULL;
  }

  for (i = 0; i < 0x17; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != NULL) {
      g_apTerrainTypeDescriptorTable[i]->Free();
      g_apTerrainTypeDescriptorTable[i] = NULL;
    }
  }

  for (i = 0; i < 7; ++i) {
    g_apNationStates[i] = NULL;
  }

  for (i = 0; i < 0x10; ++i) {
    g_apNationAuxRuntimeStateSlots[i] = NULL;
  }

  if (this != NULL) {
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
    difficultyLevel = static_cast<eDifficulty>(stream->ReadByte() & 0xff);
  }

  if (g_nSaveFormatVersion < 0x2d) {
    stream->ReadBytes(&multiplayerGameActive, 0x3c);
    scenarioMapIndexPlusOne = 0;
  } else {
    stream->ReadBytes(&multiplayerGameActive, 0x3e);
  }

  if (g_nSaveFormatVersion < 0x2e) {
    lastPersistentUnitId = 0x2711;
  } else {
    stream->ReadBytes(&lastPersistentUnitId, 4);
  }

  stream->ReadBytes(countryAvailable, sizeof(countryAvailable));

  int savedSessionRole;
  stream->ReadBytes(&savedSessionRole, 4);

  bool hasGameFlowState = multiplayerSessionRole != kSessionRoleStandalone;
  if (hasGameFlowState) {
    g_pGameFlowState->ReadFrom(stream);
  }

  if (g_nSaveFormatVersion >= 0x24) {
    stream->ReadBytes(&preferenceValues[10], 2);
  }

  if (g_nSaveFormatVersion > 0x33) {
    short selectedIndex;
    stream->ReadBytes(&selectedIndex, 2);
    mapArtSet = selectedIndex;
    g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(selectedIndex);
  } else {
    mapArtSet = (scenarioMapIndexPlusOne != 0) ? 1 : 0;
    g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(mapArtSet);
  }

  g_pMacViewMgr->ReloadMapArtAtlases();

  if (g_nSaveFormatVersion >= 0x36) {
    stream->ReadBytes(&finalCouncilYear, 2);
  }

  if (g_nSaveFormatVersion < 0x3b) {
    memset(&councilByDecade[1], 0x01, sizeof(councilByDecade) - 1);
    councilByDecade[0] = 0;
    councilByDecade[(finalCouncilYear - 0x717) / 10] = 2;
  } else {
    stream->ReadBytes(councilByDecade, sizeof(councilByDecade));
  }

  for (i = 0; i < 0x17; ++i) {
    CString emptyString(g_szEmptyString);
    sharedTextSlots[i] = emptyString;
  }

  if (g_nSaveFormatVersion >= 0x3c) {
    for (i = 0; i < 0x17; ++i) {
      stream->ReadSharedString(&sharedTextSlots[i], 0x20);
    }
  }

  g_pAssetMgr->OpenFilesFor(1);
  CreateSimObjects(false);
  CreatePlanet(0, NULL, 0);
  CreateCountries(0);

  turnStateCode = kGamePhaseShowMap;
  StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x0057c230
void TSimMgr::WriteTo(TStream* stream) {
  int i;
  TObject::WriteTo(stream);

  stream->WriteBytes(&economicTurn, 2);
  stream->WriteBytes(&activeNationSlot, 2);
  stream->WriteBytes(&turnStateCode, 2);
  stream->WriteBytes(&mode, 2);
  stream->WriteBytes(&previousTurnStateCode, 2);
  stream->WriteBytes(&previousMode, 2);
  stream->WriteBytes(&field14, 1);
  stream->WriteBytes(&numGreatPowers, 4);
  stream->WriteBytes(&numMinorCountries, 4);
  stream->WriteBytes(&turnFlowStatusFlags, 4);
  stream->WriteByte(static_cast<unsigned char>(difficultyLevel));
  stream->WriteBytes(&multiplayerGameActive, 0x3e);
  stream->WriteBytes(&lastPersistentUnitId, 4);
  stream->WriteBytes(countryAvailable, sizeof(countryAvailable));
  stream->WriteBytes(&multiplayerSessionRole, 4);

  bool hasGameFlowState = multiplayerSessionRole != kSessionRoleStandalone;
  if (hasGameFlowState) {
    g_pGameFlowState->WriteTo(stream);
  }

  stream->WriteBytes(&preferenceValues[10], 2);
  stream->WriteBytes(&mapArtSet, 2);
  stream->WriteBytes(&finalCouncilYear, 2);
  stream->WriteBytes(councilByDecade, sizeof(councilByDecade));

  for (i = 0; i < 0x17; ++i) {
    stream->WriteSharedString(&sharedTextSlots[i]);
  }
}

// FUNCTION: IMPERIALISM 0x0057c390
void TSimMgr::RebuildNationStateSlotsNoOp() {}

// FUNCTION: IMPERIALISM 0x0057c3b0
void TSimMgr::CreateSimObjects(bool flag) {
  int i;
  if ((flag && !g_bMultiplayerScenarioSetupActive) ||
      (!flag && g_bMultiplayerScenarioSetupActive)) {
    if (flag) {
      for (i = 0; i < 7; ++i) {
        nationControlModes[i] = g_aDefaultNationSetupPolicyProfiles[i][0];
        cityMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][1];
        foreignMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][2];
        defenseMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[i][3];
      }
      multiplayerGameActive = 0;
      reloadPoliticalMapState = false;
    }

    numGreatPowers = 0;
    multiplayerGameActive = (multiplayerSessionRole != kSessionRoleStandalone) ? 1 : 0;
    for (i = 0; i < 7; ++i) {
      if (countryAvailable[i]) {
        numGreatPowers++;
      }
    }

    numMinorCountries = 0;
    for (i = 7; i < 0x17; ++i) {
      if (countryAvailable[i]) {
        numMinorCountries++;
      }
    }

    if (g_pUiAnimator != NULL) {
      g_pUiAnimator->Free();
      g_pUiAnimator = NULL;
    }
    TAnimator* animator = new TAnimator();
    animator->IAnimator(0x7fffffff);
    animator->Install();
    g_pUiAnimator = animator;

    if (g_pDiplomacyTurnStateManager != NULL) {
      g_pDiplomacyTurnStateManager->Free();
      g_pDiplomacyTurnStateManager = NULL;
    }
    TDiplomacyMgr* diplomacyManager = new TDiplomacyMgr();
    diplomacyManager->IDiplomacyMgr();
    g_pDiplomacyTurnStateManager = diplomacyManager;

    if (g_pTradeMgr != NULL) {
      g_pTradeMgr->Free();
      g_pTradeMgr = NULL;
    }
    TTradeMgr* tradeManager = new TTradeMgr();
    tradeManager->ITradeMgr();
    g_pTradeMgr = tradeManager;

    if (g_pNewsMgr != NULL) {
      g_pNewsMgr->Free();
      g_pNewsMgr = NULL;
    }
    TNewsMgr* newsManager = new TNewsMgr();
    newsManager->INewsMgr();
    g_pNewsMgr = newsManager;

    if (g_pMapContextActionManager != NULL) {
      g_pMapContextActionManager->Free();
      g_pMapContextActionManager = NULL;
    }
    TArmyMgr* armyManager = new TArmyMgr();
    armyManager->IArmyMgr();
    g_pMapContextActionManager = armyManager;

    if (g_pSelectedCivilianOrderState != NULL) {
      g_pSelectedCivilianOrderState->Free();
      g_pSelectedCivilianOrderState = NULL;
    }
    TCivMgr* civilianManager = new TCivMgr();
    civilianManager->ICivMgr();
    g_pSelectedCivilianOrderState = civilianManager;

    if (g_pNavyOrderManager != NULL) {
      g_pNavyOrderManager->Free();
    }
    g_pNavyOrderManager = new TNavyMgr();
    g_pNavyOrderManager->INavyMgr();

    if (g_pTechMgr != NULL) {
      g_pTechMgr->Free();
    }
    g_pTechMgr = new TTechMgr();
    g_pTechMgr->ITechMgr();
  }
}

// FUNCTION: IMPERIALISM 0x0057c7c0
void TSimMgr::CreatePlanet(int rebuild, const char* mapName, int wrapHorizontally) {
  int i;
  if (!g_bMultiplayerScenarioSetupActive) {
    CString flavorName;
    for (i = 0; i < 0x17; ++i) {
      SetSharedStringFromMappedFlavorTextWithLengthClamp(&flavorName, i);
      sharedTextSlots[i] = flavorName;
    }
  }

  char rebuildFlag = static_cast<char>(rebuild);
  if (((rebuildFlag != 0) && (!g_bMultiplayerScenarioSetupActive)) ||
      ((rebuildFlag == 0) && (g_bMultiplayerScenarioSetupActive))) {
    if (g_pActiveMapOrderContext != NULL) {
      g_pActiveMapOrderContext->Free();
      g_pActiveMapOrderContext = NULL;
    }

    g_pActiveMapOrderContext = new TOcean();

    ResetPortZoneGlobalContextCounters();

    if (g_pGlobalMapState != NULL) {
      g_pGlobalMapState->Free();
      g_pGlobalMapState = NULL;
    }

    g_pGlobalMapState = new TMapMgr();
    g_pGlobalMapState->IMapMgr();

    if (!g_bMultiplayerScenarioSetupActive) {
      g_pGlobalMapState->hexNeighborWrapHorizontally = static_cast<char>(wrapHorizontally);
      g_pGlobalMapState->GenerateMap(NULL, const_cast<char*>(mapName));
    } else {
      g_pGlobalMapState->InitializeMap();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057c9a0
unsigned char TSimMgr::LoadScenario(int scenarioIndex) {
  scenarioMapIndexPlusOne = static_cast<short>(scenarioIndex + 1);

  if (g_pActiveMapOrderContext != NULL) {
    g_pActiveMapOrderContext->Free();
    g_pActiveMapOrderContext = NULL;
  }
  g_pActiveMapOrderContext = new TOcean();
  ResetPortZoneGlobalContextCounters();

  if (g_pGlobalMapState != NULL) {
    g_pGlobalMapState->Free();
    g_pGlobalMapState = NULL;
  }
  g_pGlobalMapState = new TMapMgr();
  g_pGlobalMapState->IMapMgr();
  g_pGlobalMapState->hexNeighborWrapHorizontally = 1;
  return static_cast<unsigned char>(
      g_pGlobalMapState->GenerateMap(g_szEmptyString, g_szEmptyString));
}

// FUNCTION: IMPERIALISM 0x0057cad0
void TSimMgr::CreateCountries(int activate) {
  int i;
  if (!g_bMultiplayerScenarioSetupActive) {
    short profileBySlot[8];
    g_pGlobalMapState->ChooseNationSetupProfilesForOpenSlots(profileBySlot);

    for (i = 0; i < 7; ++i) {
      int val = profileBySlot[i];
      cityMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][1];
      foreignMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][2];
      defenseMinisterPolicyIds[i] = g_aDefaultNationSetupPolicyProfiles[val][3];
    }
  }

  if (multiplayerSessionRole != kSessionRoleStandalone) {
    for (i = 0; i < 7; ++i) {
      int activeSessionId = g_pGameFlowState->nationSessionIds[i];
      int activeNationId = TouchSessionActiveNationId();
      if (activeSessionId == activeNationId) {
        nationControlModes[i] = 1;
      } else if (multiplayerSessionRole == kSessionRoleClient) {
        nationControlModes[i] = 4;
      } else {
        nationControlModes[i] = (activeSessionId != 0) ? 3 : 2;
      }
    }
  }

  for (i = 6; i >= 0; --i) {
    if (!countryAvailable[i]) {
      g_apNationStates[i] = NULL;
      g_apTerrainTypeDescriptorTable[i] = NULL;
    } else {
      CreateGreatPower(i, activate);
    }
  }

  for (i = 0; i < 0x17; ++i) {
    if (!countryAvailable[i]) {
      g_apSecondaryNationStateSlots[i] = NULL;
      g_apTerrainTypeDescriptorTable[i] = NULL;
    } else {
      CreateMinor(i);
    }
  }

  if (!g_bMultiplayerScenarioSetupActive) {
    g_pDiplomacyTurnStateManager->RebuildCivilianOrderCompatibilityMatrices();
    g_pViewMgr->GenerateRegions();
    g_pTechMgr->GenerateTables();
    g_pGlobalMapState->GenerateProvinceNames();
    RegenerateAllMapActionContextStatusCodes();
    g_pNewsMgr->AddMiscEvent(999, 1, true);
    g_pNewsMgr->AddMiscEvent(999, 2, true);

    const char* tagText = g_pGlobalMapState->scenarioTagText;
    if (tagText[0] == '.') {
      CString path;
      path.Format(s_PictWvGobPathFormat, tagText[1] - '0');
      if (TryGetFileMetadataForPath(&path)) {
        g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(tagText[1] - '0');
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057cda0
void TSimMgr::CreateGreatPower(int slotIndex, char activate) {
  short nationSlot = static_cast<short>(slotIndex);
  int nationIndex = nationSlot;

  if (g_apNationStates[nationIndex] != NULL) {
    g_apNationStates[nationIndex]->Free();
  }
  g_apNationStates[nationIndex] = NULL;
  g_apTerrainTypeDescriptorTable[nationIndex] = NULL;

  short setupMode = nationControlModes[nationIndex];
  if (setupMode == 1) {
    bool useClientNation = multiplayerSessionRole == kSessionRoleClient;
    if (useClientNation) {
      TGreatPower* pTVar5 = (TGreatPower*)new TClientGreatPower();
      g_apNationStates[nationIndex] = pTVar5;
    } else {
      bool useHostNation = multiplayerSessionRole == kSessionRoleHost;
      if (useHostNation) {
        TGreatPower* pTVar5 = (TGreatPower*)new THostGreatPower();
        g_apNationStates[nationIndex] = pTVar5;
      } else {
        TGreatPower* pTVar5 = new TGreatPower();
        g_apNationStates[nationIndex] = pTVar5;
      }
    }
    g_apNationStates[nationIndex]->IGreatPower(slotIndex, 1);
    g_apTerrainTypeDescriptorTable[nationIndex] = g_apNationStates[nationIndex];
    if (!g_bMultiplayerScenarioSetupActive) {
      activeNationSlot = nationSlot;
      g_pMacViewMgr->RefreshCityCapabilityUiHandlesForActiveNation();
    }
    if (!g_bMultiplayerScenarioSetupActive) {
      bool suspendPrimaryEventQueue = multiplayerSessionRole != kSessionRoleStandalone;
      if (suspendPrimaryEventQueue) {
        g_pGameFlowState->processPrimaryEventQueue = 0;
      }
      if (activate != 0) {
        TGreatPower* nationState = g_apNationStates[nationIndex];
        TCity* city = nationState != NULL ? nationState->city : NULL;
        nationState->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      bool resumePrimaryEventQueue = multiplayerSessionRole != kSessionRoleStandalone;
      if (resumePrimaryEventQueue) {
        g_pGameFlowState->processPrimaryEventQueue = 1;
      }
    }
  } else if (setupMode == 4) {
    TGreatPower* pTVar5 = (TGreatPower*)new TRemoteGreatPower();
    g_apNationStates[nationIndex] = pTVar5;
    pTVar5->IGreatPower(slotIndex, g_pGameFlowState->nationSessionIds[nationIndex] != 0);
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
      TCity* city = pTVar5 != NULL ? pTVar5->city : NULL;
      pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
    }
  } else if (setupMode == 3) {
    TGreatPower* pTVar5 = (TGreatPower*)new TProxyGreatPower();
    pTVar5->IGreatPower(slotIndex, 1);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (!g_bMultiplayerScenarioSetupActive) {
      if (activate != 0) {
        TCity* city = pTVar5 != NULL ? pTVar5->city : NULL;
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      g_pDiplomacyTurnStateManager->SetRelationship(slotIndex, slotIndex, 0x100);
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
    TAutoGreatPower* pTVar5 = new TAutoGreatPower();
    pTVar5->IAutoGreatPower(slotIndex, 2, cityMinisterPolicyIds[nationIndex],
                            foreignMinisterPolicyIds[nationIndex],
                            defenseMinisterPolicyIds[nationIndex]);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (!g_bMultiplayerScenarioSetupActive) {
      if (activate != 0) {
        TCity* city = pTVar5 != NULL ? pTVar5->city : NULL;
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      pTVar5->CreateInitialMissions();
      pTVar5->NameUnits();
    }
  } else {
    g_apNationStates[nationIndex] = NULL;
    g_apTerrainTypeDescriptorTable[nationIndex] = NULL;
  }

  if (nationSlot == activeNationSlot) {
    bool useSessionDisplayName = multiplayerSessionRole != kSessionRoleStandalone;
    if (useSessionDisplayName) {
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
        CString nationName(g_cstrCountryNameSettingValue);
        g_apTerrainTypeDescriptorTable[nationIndex]->SetNationDisplayNameAndLocalizationSlotRef(
            nationName);
      }
      {
        CString nationName(g_cstrCountryNameSettingValue);
        g_apTerrainTypeDescriptorTable[nationIndex]->identitySharedString1 = nationName;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057d520
void TSimMgr::CreateMinor(int slotIndex) {
  short nationSlot = static_cast<short>(slotIndex);
  if (nationSlot < kMajorNationCount) {
    g_apSecondaryNationStateSlots[nationSlot] = NULL;
    return;
  }

  int nationIndex = nationSlot;
  TMinor* minor = NULL;
  if (nationIndex < numMinorCountries + 7 && multiplayerSessionRole == kSessionRoleClient) {
    if (g_apSecondaryNationStateSlots[nationIndex] != NULL) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = NULL;
    g_apTerrainTypeDescriptorTable[nationIndex] = NULL;
    minor = new TRemoteMinor();
    minor->IMinor(static_cast<NationSlot>(slotIndex));
  } else if (nationIndex < numMinorCountries + 7) {
    if (g_apSecondaryNationStateSlots[nationIndex] != NULL) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = NULL;
    g_apTerrainTypeDescriptorTable[nationIndex] = NULL;

    minor = new TMinor();
    minor->IMinor(static_cast<NationSlot>(slotIndex));

    g_apSecondaryNationStateSlots[nationIndex] = minor;
    g_apTerrainTypeDescriptorTable[nationIndex] = minor;

    if (!g_bMultiplayerScenarioSetupActive) {
      minor->InitialMilitia();

      short cityRecordIndex =
          g_pGlobalMapState->terrainStateTable[static_cast<short>(minor->homeTileIndex)]
              .cityRecordIndex;
      for (int remainingOrders = 0; remainingOrders < 2; ++remainingOrders) {
        TMilitaryUnit* order = new TMilitaryUnit();
        order->IMilitaryUnit(2, cityRecordIndex, slotIndex, 0);
        order->SetOrders(static_cast<UnitOrder>(2), -1);
      }

      minor->NameUnits();
    }
    return;
  } else {
    if (g_apSecondaryNationStateSlots[nationIndex] != NULL) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
  }

  g_apSecondaryNationStateSlots[nationIndex] = minor;
  g_apTerrainTypeDescriptorTable[nationIndex] = minor;
}

// FUNCTION: IMPERIALISM 0x0057d7a0
void TSimMgr::DoPerTurnMissionAIStuff(int replanMode) {
  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  RecomputeNationOrderPriorityMetrics();

  short nationSlot = 0;
  TGreatPower** nation = g_apNationStates;
  do {
    if (nationSlot != -1) {
      TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
      if (country != NULL && (nationSlot >= 7 || country->encodedNationSlot < 100 ||
                              country->encodedNationSlot >= 200)) {
        (*nation)->ReassessMissions(replanMode);
      }
    }
    ++nation;
    ++nationSlot;
  } while (nation < &g_apNationStates[kMajorNationCount]);
}

// FUNCTION: IMPERIALISM 0x0057d830
void TSimMgr::GetSeason(CString* destString) {
  short offset = economicTurn % 4;
  GetString(10000, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0057d870
void TSimMgr::SetDifficultyLevel(eDifficulty difficulty) {
  bool zeroFlag = false;
  difficultyLevel = difficulty;
  if (difficulty != kDifficultyIntroductory) {
    if (difficulty > kDifficultyIntroductory && difficulty <= kDifficultyNighOnImpossible) {
      this->preferenceValues[10] = zeroFlag;
      return;
    }
  } else {
    zeroFlag = true;
  }
  this->preferenceValues[10] = zeroFlag;
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
    reloadPoliticalMapState = true;
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
void TSimMgr::EnterOptionalPhase(eGamePhaseNewStyle gamePhase) {
  bool mayEnterPhase = IsNationEligibleForOptionalPhase(activeNationSlot);
  if (!mayEnterPhase) {
    switch (gamePhase) {
    case kGamePhaseOptionalDealBook:
    case kGamePhaseOptionalTradeOverview:
    case kGamePhaseOptionalDiplomacyMap:
    case kGamePhaseOptionalTransport:
    case kGamePhaseOptionalCityScreen:
    case kGamePhaseOptionalTechStore:
      return;
    }
  }

  eGamePhaseNewStyle oldPhase = this->turnStateCode;
  this->turnStateCode = gamePhase;
  this->previousMode = mode;
  previousTurnStateCode = oldPhase;
  StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x0057da70
void TSimMgr::AdvanceGlobalTurnStateMachine() {
  // Source evidence: retail constructs this CString before the defer check.
  CString emptyString;

  if (turnStateCode == kGamePhaseAdvanceSeason && g_nTurnCooldownDeferCounter > 0) {
    --g_nTurnCooldownDeferCounter;
  }
  mode = turnStateCode;

  switch (turnStateCode) {
  case kGamePhaseStartup:
    turnStateCode = kGamePhaseSetUpMap;
    if (!g_bTurnFlowBootstrapComplete) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
      break;
    }
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventMainMenu), 0);
    break;

  case kGamePhaseStartGame: {
    turnStateCode = kGamePhaseAdvanceSeason;
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      nation->AssertValid();
      if (!nation->IsRemote() && !g_bMultiplayerScenarioSetupActive) {
        nation->PlaceCity(-1, 0);
      }
    }
    if (!g_bMultiplayerScenarioSetupActive) {
      if (scenarioMapIndexPlusOne == 0) {
        if (multiplayerSessionRole == kSessionRoleStandalone) {
          NameCapitals();
        }
      } else {
        ProcessScenarioScript();
      }
    }
    TGreatPower* activeNation = g_apNationStates[activeNationSlot];
    activeNation->InitializeTradeStatus();
    activeNation->SetTradeBids();
    g_pHelpMgr->ResetHelpSetRanksAndFlags();
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
      turnStateCode = kGamePhaseNetworkSync;
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseSetUpMap:
    turnStateCode = kGamePhaseStartGame;
    if (reloadPoliticalMapState) {
      g_pSimMgr->CreateSimObjects(true);
      g_pSimMgr->CreatePlanet(1, s_Chunk, 1);
    }
    if (g_bMultiplayerScenarioSetupActive) {
      break;
    }
    CreateCountries(1);
    if (g_pSimMgr->difficultyLevel > kDifficultyEasy && scenarioMapIndexPlusOne == 0) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector),
                                    activeNationSlot);
    } else {
      StartNextPhase();
    }
    break;

  case kGamePhaseShowMap:
    turnStateCode = kGamePhaseEndTurn;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap),
                                  g_pSimMgr->activeNationSlot);
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      if (activeNationSlot == -1 || g_apTerrainTypeDescriptorTable[activeNationSlot] == NULL ||
          (activeNationSlot <= 6 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot >= 100 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot <= 199)) {
        StartNextPhase();
      }
    }
    break;

  case kGamePhaseEndTurn: {
    const bool alertsPending = ShowTurnAlertsForActiveNation();
    alertsPendingFlag = alertsPending;
    if (alertsPending) {
      break;
    }
    bool continueTurn = true;
    while (multiplayerSessionRole != kSessionRoleClient && ReturnTrueStub() == 0) {
      CString message;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2745, 10);
      if (!g_pViewMgr->ModalMessage(message, g_ptTurnTransitionModalMessage, 1, 1)) {
        continueTurn = false;
        break;
      }
    }
    if (!continueTurn) {
      break;
    }
    turnStateCode = kGamePhaseDiplomacy;
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, kGamePhaseDiplomacy);
      turnStateCode = kGamePhaseNetworkSync;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseDiplomacy: {
    turnStateCode = kGamePhaseTrade;
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
    }
    if (multiplayerSessionRole != kSessionRoleHost) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (multiplayerSessionRole == kSessionRoleStandalone) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != NULL && nation->diplomacyEligibility != 0 &&
            nation->proposalQueue->GetSize() > 0) {
          g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
          g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap),
                                        activeNationSlot);
          break;
        }
      }
    } else if (IsNationEligibleForOptionalPhase(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), activeNationSlot);
    }
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != NULL) {
        nation->ReplyToDiplomacyOffers();
      }
    }
    if (multiplayerSessionRole == kSessionRoleStandalone ||
        (multiplayerSessionRole == kSessionRoleHost &&
         !IsNationEligibleForOptionalPhase(activeNationSlot))) {
      TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
      nextCommand->PostThyself();
    }
    break;
  }

  case kGamePhaseTrade: {
    turnStateCode = kGamePhaseCivilians;
    g_pDiplomacyTurnStateManager->SelectPriorityNationIndicesForMinorCapabilityRows();
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
      g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), activeNationSlot);
      g_pViewMgr->ShowOfferSheet(-1, 0, 0, 0, 0x16);
    }
    if (multiplayerSessionRole != kSessionRoleClient) {
      DoTrade();
    }
    break;
  }

  case kGamePhaseCityAndTransport: {
    turnStateCode = kGamePhaseLossCheck;
    DoCityAndTransport();
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
      turnStateCode = kGamePhaseNetworkSync;
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseCivilians: {
    turnStateCode = kGamePhaseMilitary;
    if (multiplayerSessionRole != kSessionRoleClient) {
      DoCivilians();
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseMilitary: {
    turnStateCode = kGamePhaseCombat;
    g_pSimMgr->DoMilitary();
    StartNextPhase();
    break;
  }

  case kGamePhaseLossCheck: {
    turnStateCode = kGamePhaseDealBook;
    bool actionNeeded = false;
    for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == NULL) {
        continue;
      }
      if (!nation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage()) {
        continue;
      }
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      activeNation->SorryYouLose();
      actionNeeded = true;
    }
    if (!actionNeeded) {
      StartNextPhase();
    }
    break;
  }

  case kGamePhaseDealBook: {
    turnStateCode = kGamePhaseCouncil;
    if (IsNationEligibleForOptionalPhase(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDealBook), activeNationSlot);
      g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
      break;
    }
    if (!IsNationEligibleForOptionalPhase(activeNationSlot)) {
      StartNextPhase();
    }
    break;
  }

  case kGamePhaseBattleReport: {
    turnStateCode = kGamePhaseEliminations;
    if (g_pMapContextActionManager->HasBattlesToReport() &&
        IsNationEligibleForOptionalPhase(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventBattleReport), activeNationSlot);
      break;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseCouncil: {
    turnStateCode = kGamePhaseAdvanceSeason;
    if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot != -1) {
      const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot;
      turnStateCode =
          lastProcessed == activeNationSlot ? kGamePhaseCouncilVictory : kGamePhaseCouncilDefeat;
    }
    const short tickA = GetEconomicTurn();
    const short tickB = GetEconomicTurn();
    if (tickB % 0x28 != 0 || councilByDecade[tickA / 0x28] == 0) {
      StartNextPhase();
    } else {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic),
                                    activeNationSlot);
    }
    break;
  }

  case kGamePhaseNews: {
    turnStateCode = kGamePhaseTurnStart;
    g_pAssetMgr->OpenFilesFor(0xa);
    g_pNewsMgr->StartNewsPhase();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNewspaperStatus), activeNationSlot);
    for (short nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      g_apNationStates[nationSlot]->MarkAllPendingStatusFlagsHandled();
    }
    bool saveTurn = false;
    if (g_nTurnCooldownDeferCounter < 1) {
      g_nTurnCooldownDeferCounter = 0;
      g_nTurnCooldownSideFlag = 1;
      saveTurn = true;
    } else {
      const int phaseFlags = GetEconomicTurn();
      if ((phaseFlags & 0xf) == 10) {
        saveTurn = true;
      }
    }
    if (saveTurn) {
      if (multiplayerSessionRole == kSessionRoleStandalone) {
        SaveGameWithModeAndOptionalLabel(0xa1, 0);
      } else if (multiplayerSessionRole == kSessionRoleHost) {
        g_pGameFlowState->AttemptSave(0xa1, 0, true);
      }
    }
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      if (!IsNationEligibleForOptionalPhase(activeNationSlot)) {
        StartNextPhase();
      }
    }
    break;
  }

  case kGamePhaseAdvanceSeason: {
    turnStateCode = kGamePhaseTechnology;
    alertsPendingFlag = 0;
    turnFlowStatusFlags = 0;
    AdvanceSeason();
    StartNextPhase();
    break;
  }

  case kGamePhaseTechnology: {
    turnStateCode = kGamePhaseNews;
    bool actionNeeded = true;
    const short capabilityBefore = g_pTechMgr != NULL ? g_pTechMgr->marker262 : 0;
    g_pTechMgr->CheckForAdvances();
    if (capabilityBefore == (g_pTechMgr != NULL ? g_pTechMgr->marker262 : 0)) {
      turnFlowStatusFlags |= 0x40;
    }
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (g_pSimMgr->activeNationSlot == nationSlot && g_nTurnCooldownDeferCounter < 1) {
        g_nTurnCooldownDeferCounter = 0;
        g_nTurnCooldownSideFlag = 1;
        if (IsNationEligibleForOptionalPhase(activeNationSlot)) {
          short unlockSlot = g_pTechMgr->GetNextNewAdvance(static_cast<short>(nationSlot));
          if (unlockSlot != -1) {
            g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTechnologyAdvance),
                                          unlockSlot);
            actionNeeded = false;
          }
          continue;
        }
      }
      short unlockSlot = g_pTechMgr->GetNextNewAdvance(static_cast<short>(nationSlot));
      while (unlockSlot != -1) {
        unlockSlot = g_pTechMgr->GetNextNewAdvance(static_cast<short>(nationSlot));
      }
    }
    if (actionNeeded) {
      StartNextPhase();
    }
    break;
  }

  case kGamePhaseTurnStart: {
    turnStateCode = kGamePhaseEndTurn;
    g_pAssetMgr->OpenFilesFor(0x13);
    g_pGlobalMapState->ShowMap();
    g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();
    for (short nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == NULL || nationSlot == -1) {
        continue;
      }
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      nation->InitializeDiplomacyNotices();
      nation->DisplayTurnStartEvents();
    }
    g_pSfxPlaybackSystem->ResetPlayList();
    g_pSfxPlaybackSystem->AddToPlayList(2);
    g_pSfxPlaybackSystem->AddToPlayList(3);
    g_pSfxPlaybackSystem->PlayRandomTrack();
    if (!IsNationEligibleForOptionalPhase(activeNationSlot)) {
      StartNextPhase();
    }
    break;
  }

  case kGamePhaseNetworkSync: {
    turnStateCode = g_pGameFlowState->resumePhase;
    g_pGameFlowState->HandleTurnResumeStateTelemetry();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNetworkGameOptions),
                                  activeNationSlot);
    break;
  }

  case kGamePhaseCombat: {
    turnStateCode = kGamePhaseProduction;
    g_pMapContextActionManager->DoCombatMoves();
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
      turnStateCode = kGamePhaseNetworkSync;
    }
    break;
  }

  case kGamePhaseProduction: {
    turnStateCode = kGamePhaseBattleReport;
    g_pNavyOrderManager->ClearAllTransientOrders();
    if (multiplayerSessionRole != kSessionRoleClient) {
      g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
      RecomputeNationOrderPriorityMetrics();
      for (short nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (nationSlot == -1 || g_apTerrainTypeDescriptorTable[nationSlot] == NULL) {
          continue;
        }
        if (nationSlot < 7 && g_apTerrainTypeDescriptorTable[nationSlot]->IsProtectorate()) {
          continue;
        }
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != NULL) {
          nation->ReassessMissions(0);
        }
      }
    }
    for (short nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      g_apNationStates[nationSlot]->AddPurchasedItems();
    }
    const short tickA = GetEconomicTurn();
    const short tickB = GetEconomicTurn();
    if (((tickB % 0x28) == 0) && (councilByDecade[tickA / 0x28] != 0) &&
        multiplayerSessionRole != kSessionRoleClient) {
      g_pDiplomacyTurnStateManager->ConveneCouncil(councilByDecade[tickA / 0x28]);
    }
    if (multiplayerSessionRole != kSessionRoleStandalone) {
      g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
      turnStateCode = kGamePhaseNetworkSync;
    }
    StartNextPhase();
    break;
  }

  case kGamePhaseCouncilDefeat:
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    break;

  case kGamePhaseEliminations: {
    turnStateCode = kGamePhaseCityAndTransport;
    bool actionNeeded = false;
    {
      const short localizationNation = g_pSimMgr->activeNationSlot;
      TGreatPower* localizationNationState = g_apNationStates[localizationNation];
      if (localizationNationState != NULL) {
        const short encoded = localizationNationState->encodedNationSlot;
        if (encoded > 99 && encoded < 200) {
          TGreatPower* activeNation = g_apNationStates[activeNationSlot];
          activeNation->SorryYouLose();
          actionNeeded = true;
        }
      }
    }
    for (int removeNationSlot = 0; removeNationSlot < kMajorNationCount; ++removeNationSlot) {
      if (g_apTerrainTypeDescriptorTable[removeNationSlot] == NULL ||
          g_apNationStates[removeNationSlot] == NULL) {
        continue;
      }
      if (g_apNationStates[removeNationSlot]->ownedRegionList->GetSize() == 0) {
        EliminateGP(static_cast<short>(removeNationSlot));
      }
    }
    for (int secondaryIndex = 7; secondaryIndex < 0x17; ++secondaryIndex) {
      TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
      if (secondaryNation != NULL && secondaryNation->ownedRegionList->GetSize() == 0) {
        for (short percentNationSlot = 0; percentNationSlot < kMajorNationCount;
             ++percentNationSlot) {
          if (!IsNationEligibleForOptionalPhase(percentNationSlot)) {
            continue;
          }
          g_apNationStates[percentNationSlot]->NewStatusFor(secondaryIndex, 500);
        }
      }
    }
    if (actionNeeded) {
      break;
    }
    int eligibleMinorCount = 0;
    for (int countNationSlot = 0; countNationSlot < kMajorNationCount; ++countNationSlot) {
      if (IsNationEligibleForOptionalPhase(static_cast<short>(countNationSlot))) {
        ++eligibleMinorCount;
      }
    }
    if (eligibleMinorCount == 1 && IsNationEligibleForOptionalPhase(activeNationSlot)) {
      actionNeeded = true;
      AddHighScore();
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    }
    if (!actionNeeded) {
      StartNextPhase();
    }
    break;
  }

  case kGamePhaseCouncilVictory:
    AddHighScore();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    break;

  case kGamePhaseOptionalDealBook:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDealBook), activeNationSlot);
    break;

  case kGamePhaseOptionalCredits:
    turnStateCode = kGamePhaseShowMap;
    g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventCredits));
    break;

  case kGamePhaseOptionalNetworkGameOptions:
    turnStateCode = kGamePhaseShowMap;
    g_pAmbitApplication->PostTurnEventCodeMessage(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    break;

  case kGamePhaseOptionalBattleReport:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventBattleReport), activeNationSlot);
    break;

  case kGamePhaseOptionalNewspaper:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNewspaperStatus), activeNationSlot);
    break;

  case kGamePhaseOptionalTradeOverview:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] !=
                                          0
                                      ? kTurnEventIndustryOverview
                                      : kTurnEventTradeOverview,
                                  activeNationSlot);
    break;

  case kGamePhaseOptionalDiplomacyMap:
    turnStateCode = kGamePhaseShowMap;
    g_apNationStates[activeNationSlot]->SetDiplomacyPolicies();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), activeNationSlot);
    g_pDiplomacyTurnStateManager->SetLastDiploEffort();
    break;

  case kGamePhaseOptionalTransport:
    turnStateCode = kGamePhaseShowMap;
    g_apNationStates[activeNationSlot]->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTransport), activeNationSlot);
    break;

  case kGamePhaseOptionalCityScreen:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCityProduction), activeNationSlot);
    break;

  case kGamePhaseOptionalGamePreferences:
    turnStateCode = kGamePhaseShowMap;
    g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventGamePreferences));
    break;

  case kGamePhaseOptionalUnitHistory:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventUnitHistory), activeNationSlot);
    break;

  case kGamePhaseOptionalTechStore:
    turnStateCode = kGamePhaseShowMap;
    turnFlowStatusFlags |= 0x40;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTechnologyStore), activeNationSlot);
    break;

  case kGamePhaseOptionalGameStatus:
    turnStateCode = kGamePhaseShowMap;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventGameStatus), activeNationSlot);
    break;

  case kGamePhaseOptionalSaveGame:
    turnStateCode = kGamePhaseShowMap;
    g_nSaveFormatVersion = -1;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), activeNationSlot);
    break;

  case kGamePhaseOptionalLoadGame:
    turnStateCode = kGamePhaseShowMap;
    g_nSaveFormatVersion = -2;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), activeNationSlot);
    break;

  default:
    break;
  }
}

// FUNCTION: IMPERIALISM 0x0057f110
bool TSimMgr::InLinearPhase() {
  eGamePhaseNewStyle phase = turnStateCode;
  return phase < kGamePhaseShowMap || phase > kGamePhaseEndTurn;
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
      (*nation)->CalculatePotentials();
      (*nation)->ExecuteNationPendingActionStateMachine();
      (*nation)->FinishCityPhase();
      (*nation)->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    }
    --nation;
    --nationSlot;
  } while (nation >= g_apNationStates);
}

// FUNCTION: IMPERIALISM 0x0057f200
void TSimMgr::DoCivilians() {
  g_pSelectedCivilianOrderState->ResolveCivilianDisputes();
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      g_apNationStates[nationSlot]->MoveCivilians();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057f280
void TSimMgr::DoMilitary() {
  int isClient = multiplayerSessionRole == kSessionRoleClient;
  if (!isClient) {
    g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  }

  for (int terrainSlot = 0; terrainSlot < kTerrainTypeDescriptorTableCount; ++terrainSlot) {
    if (IsNationEligibleForOptionalPhase(static_cast<short>(terrainSlot))) {
      g_apTerrainTypeDescriptorTable[terrainSlot]->GrowMilitia();
    }
  }

  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (!IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationSlot];
    nation->PayForMilitary();
    nation->SelectAndQueueAdvisoryMapMissions();
    nation->MoveArmy();
  }

  g_pMapContextActionManager->CleanUpStacks();
  isClient = multiplayerSessionRole == kSessionRoleClient;
  if (!isClient) {
    g_pNavyOrderManager->PrepareToCarryOutAllOrders(1);
    g_pNavyOrderManager->CarryOutOrders();
  }
}

// FUNCTION: IMPERIALISM 0x0057f3c0
void TSimMgr::DoTrade() {
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), activeNationSlot);

  for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
    if (g_apNationStates[nationSlot] != 0) {
      g_apNationStates[nationSlot]->InitializeDealBook();
    }
  }

  g_pTradeMgr->ResetNationMetricRowsAndClearCategoryRankLists();
  g_pTradeMgr->StartTradePhase();
  g_pTradeMgr->SetMinorsTradeBids();
  g_pTradeMgr->TallyTradeBids();
  g_pTradeMgr->CalculateNewWorldPrices();
  g_pTradeMgr->CalculateDealOrder();

  bool shouldSendTradeBook = multiplayerSessionRole != kSessionRoleStandalone;
  if (shouldSendTradeBook) {
    g_pGameFlowState->SendTradeBook();
  }
  g_pTradeMgr->StartDeals();
}

// FUNCTION: IMPERIALISM 0x0057f490
int TSimMgr::PlayerLost() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057f4b0
void TSimMgr::SetFlags(unsigned int flags) {
  turnFlowStatusFlags |= flags;
}

// FUNCTION: IMPERIALISM 0x0057f4d0
bool TSimMgr::TestTurnFlowStatusFlagMask(unsigned int mask) {
  return (mask & turnFlowStatusFlags) != 0;
}

// FUNCTION: IMPERIALISM 0x0057f4f0
bool TSimMgr::AllHumansFinished() {
  bool finished = true;
  for (TGreatPower** nation = g_apNationStates; nation < g_apNationStates + 7; ++nation) {
    if ((*nation)->turnFinished == 0) {
      finished = false;
      break;
    }
  }
  return finished;
}

// FUNCTION: IMPERIALISM 0x0057f530
void TSimMgr::ResetTurnFlags() {
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation->diplomacyEligibility != 0) {
      nation->turnFinished = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057f570
void TSimMgr::MultiSync() {
  bool hasMultiplayerSession = multiplayerSessionRole != kSessionRoleStandalone;
  if (hasMultiplayerSession) {
    g_pGameFlowState->SetSyncPhases(mode, turnStateCode);
    turnStateCode = kGamePhaseNetworkSync;
  }
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
  CString suffixTemplate;
  CString numberStr;
  numberStr.Format(g_szDecimalFormat, value);

  // English ordinal suffix selection (1st/2nd/3rd/Nth, with the 11/12/13 exceptions).
  int suffixCode;
  switch (value % 10) {
  case 1:
    suffixCode = (value != 11) ? 0 : 3;
    break;
  case 2:
    suffixCode = (value != 12) ? 1 : 3;
    break;
  case 3:
    suffixCode = (value == 13) ? 3 : 2;
    break;
  default:
    suffixCode = 3;
    break;
  }

  g_pSimMgr->GetString(0x275f, suffixCode, &suffixTemplate);
  scanBracketExpressions(this, destString, static_cast<LPCSTR>(suffixTemplate),
                         static_cast<LPCSTR>(numberStr));
}

// FUNCTION: IMPERIALISM 0x0057fe90
void TSimMgr::GetCommodityName(short offset, CString* destString) {
  GetString(0x2711, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0057fec0
void TSimMgr::ReinitializeRandomSeed() {
  srand(static_cast<unsigned int>(ClockDerivedPrngSeed()));
}

// FUNCTION: IMPERIALISM 0x00580760
void TSimMgr::GetString(short codeGroup, short offset, CString* destString) {
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(destString, codeGroup, offset + 1);
}

// FUNCTION: IMPERIALISM 0x00580790
CString TSimMgr::DiplomacyNoticeString(const DiplomacyNotice* notice) {
  CString result;
  CString countryName;
  CString formattedValue;

  bool rejected = false;
  short code = notice->policyOrGrantCode;
  short nationSlot = notice->nationSlot;
  if (code < 0) {
    rejected = true;
    code = static_cast<short>(-code);
  }

  g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&countryName);

  switch (code) {
  case 5:
  case 7:
  case 8:
  case 9:
  case 10:
  case 11:
  case 12: {
    CString commodityName;
    g_pSimMgr->GetCommodityName(code, &commodityName);
    CString noticeText = "Shortage of " + commodityName + " in " + countryName + ".";
    result = noticeText;
    break;
  }
  case kDiplomacyProposalJoinEmpire:
    if (rejected) {
      CString noticeText = countryName + " has rejected our invitation to join our Empire!";
      result = noticeText;
    } else {
      CString noticeText =
          "Our power grows! " + countryName + " has accepted our invitation to join our Empire!";
      result = noticeText;
    }
    break;
  case kDiplomacyProposalAlliance:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of an alliance";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of an alliance";
      result = noticeText;
    }
    break;
  case kDiplomacyProposalNonAggressionPact:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of a non-aggression pact";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of a non-aggression pact";
      result = noticeText;
    }
    break;
  case kDiplomacyProposalPeaceTreaty:
    if (rejected) {
      CString noticeText = countryName + " has rejected our offer of a peace treaty.";
      result = noticeText;
    } else {
      CString noticeText = countryName + " has accepted our offer of a peace treaty.";
      result = noticeText;
    }
    break;
  case kDiplomacyProposalDeclareWar: {
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

// FUNCTION: IMPERIALISM 0x00581220
int TSimMgr::GetNumMinorCountries() const {
  return numMinorCountries;
}

// FUNCTION: IMPERIALISM 0x00581240
int TSimMgr::GetNumCountries() {
  return numMinorCountries + numGreatPowers;
}

// FUNCTION: IMPERIALISM 0x00581260
NationSlot TSimMgr::GetPlayerCountry() {
  return activeNationSlot;
}

// FUNCTION: IMPERIALISM 0x00581280
bool TSimMgr::ReallyInTheGame(NationSlot nationSlot) {
  if (nationSlot == -1) {
    return false;
  }

  TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
  if (terrainDescriptor == 0) {
    return false;
  }

  if (nationSlot < kMajorNationCount) {
    if (terrainDescriptor != 0) {
      short profileType = terrainDescriptor->encodedNationSlot;
      bool inReservedProfileBand = profileType >= 100 && profileType < 200;
      if (inReservedProfileBand) {
        return false;
      }
    }
  }

  return true;
}

// FUNCTION: IMPERIALISM 0x00581300
void TSimMgr::EliminateGP(NationSlot nationSlot) {
  for (short i = 0; i < 7; ++i) {
    if (i != nationSlot && i != -1) {
      TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[i];
      if (terrainDescriptor != 0) {
        if (i >= 7 || terrainDescriptor->encodedNationSlot < 100 ||
            terrainDescriptor->encodedNationSlot >= 200) {
          g_apNationStates[i]->NewStatusFor(nationSlot, 500);
        }
      }
    }
  }

  if (g_apNationStates[nationSlot] != 0) {
    g_apNationStates[nationSlot]->Free();
  }
  g_apNationStates[nationSlot] = 0;
  g_apTerrainTypeDescriptorTable[nationSlot] = 0;
  countryAvailable[nationSlot] = false;
  --numGreatPowers;
  g_pDiplomacyTurnStateManager->RemoveNationSlotAndNotifyPeers(nationSlot);
}

// FUNCTION: IMPERIALISM 0x005813d0
void TSimMgr::NotifyActiveNationLost() {
  g_apNationStates[activeNationSlot]->SorryYouLose();
}

// FUNCTION: IMPERIALISM 0x00581400
void TSimMgr::UpdatePreferences(bool writeBack) {
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
void TSimMgr::AddHighScore() {
  CString path;
  CString ownNationName;
  GetString(0x2737, 0xd, &ownNationName);

  AssignScoresDatPathToSharedString(&path);
  FILE* file = fopen(path, g_szLiteralRb);

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

  g_apNationStates[activeNationSlot]->GenerateGameScore();
  int score = g_apNationStates[activeNationSlot]->gameScoreRows[TGreatPower::kGameScoreTotal];

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

    FILE* writeFile = fopen(path, g_szLiteralWb);
    for (int i = 0; i < 10; ++i) {
      fwrite(&scoreValues[i], 4, 1, writeFile);
      fwrite(scoreRecords[i], 0x20, 1, writeFile);
    }
    fclose(writeFile);
  }
}

// Random-game setup resets the existing manager; other events replace it.
// FUNCTION: IMPERIALISM 0x00581870
void ReinitializeGameFlowAndPostTurnEventCode(TurnEventId eventCode) {
  if (g_pHelpMgr != 0) {
    g_pHelpMgr->CheckHelp(kTurnEventMainMenu);
  }
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->Free();
    g_pGameFlowState = new TMultiplayerMgr();
    g_pGameFlowState->IMultiplayerMgr(0);
  }
  if (eventCode == kTurnEventRandomGameSetup) {
    TSimMgr* simMgr = g_pSimMgr;
    simMgr->economicTurn = 0;
    simMgr->activeNationSlot = -1;
    simMgr->field14 = 0;
    simMgr->turnStateCode = kGamePhaseStartup;
    simMgr->turnFlowStatusFlags = 0;
    simMgr->lastPersistentUnitId = 0;
    simMgr->councilByDecade[0] = 0;
    memset(&simMgr->councilByDecade[1], 0x01, sizeof(simMgr->councilByDecade) - 1);
    simMgr->councilByDecade[10] = 2;
    CFileStatus conanFileStatus;
    CFile::GetStatus(g_szConanCheatFileName, conanFileStatus);
    g_bRandomMapDeveloperCheatFlag = false;
    simMgr->ReinitializeRandomSeed();
    g_pSimMgr->turnStateCode = kGamePhaseSetUpMap;
    g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(eventCode));
  } else {
    g_pSimMgr->Free();
    g_pSimMgr = new TSimMgr();
    g_pSimMgr->ISimMgr();
    g_pSimMgr->StartNextPhase();
    if (eventCode != 0) {
      g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(eventCode));
    }
  }
  g_bTurnFlowBootstrapComplete = true;
}

// FUNCTION: IMPERIALISM 0x00581ae0
void TSimMgr::SelectMapArtSet(short index) {
  mapArtSet = index;
  g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(index);
  g_pMacViewMgr->ReloadMapArtAtlases();
}

// FUNCTION: IMPERIALISM 0x00581b20
CString TSimMgr::GetCountryName(short slot) {
  CString name = g_pLanguageMgr->StripCodeStr(sharedTextSlots[slot]);
  return name;
}

// FUNCTION: IMPERIALISM 0x00581bc0
CString TSimMgr::GetCountryNameWithCode(short slot) {
  return sharedTextSlots[slot];
}

// FUNCTION: IMPERIALISM 0x00581c00
void TSimMgr::NameCapitals() {
  for (short nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
    if (country == 0) {
      continue;
    }

    const short cityRecordIndex = static_cast<short>(country->GetCapitolProvince());
    CString capitalNameTemplate;
    CString countryName = GetCountryName(nationSlot);
    CString capitalName;
    GetString(0x272a, 0, &capitalNameTemplate);
    scanBracketExpressions(this, &capitalName, static_cast<LPCSTR>(capitalNameTemplate),
                           static_cast<LPCSTR>(countryName));
    g_pGlobalMapState->SetProvinceName(cityRecordIndex, &capitalName);
  }
}

// FUNCTION: IMPERIALISM 0x00581e60
void TSimMgr::ProcessScenarioScript() {
  CString scenarioPath;
  newsEventsSuppressed = true;
  g_nSaveFormatVersion = -3;
  g_bScenarioScriptTerminationRequested = false;
  g_nScenarioScriptInstructionCount = 0;

  g_pAssetMgr->GetScenarioFileName(static_cast<short>(scenarioMapIndexPlusOne) - 1, 2,
                                   &scenarioPath);

  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    CString ordinalText;
    ordinalText.Format(g_szDecimalFormat, zone->GetContextOrdinalOrInvalid());
    zone->displayName = ordinalText;
  }

  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(scenarioPath);
  int resourceSize = g_pAssetMgr->GetResourceStreamSize(stream);
  unsigned char* buffer = new unsigned char[resourceSize];
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, buffer, &resourceSize);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);

  STurnInstructionCursor instruction;
  instruction.tokenCursor = reinterpret_cast<unsigned int*>(buffer);
  unsigned int instructionTag;
  instructionTag = 0;
  while (reinterpret_cast<unsigned char*>(instruction.tokenCursor) < buffer + resourceSize &&
         instructionTag != kControlTagTERM && !g_bScenarioScriptTerminationRequested) {
    instructionTag = *instruction.tokenCursor;
    int instructionCount = g_nScenarioScriptInstructionCount;
    DECODE_SCENARIO_DWORD_TOKEN(instructionTag);
    ++instruction.tokenCursor;
    ++instructionCount;
    g_nScenarioScriptInstructionCount = instructionCount;

    if (instructionTag != kControlTagTERM) {
      int handlerIndex = 0;
      while (handlerIndex < 27 &&
             g_anScenarioScriptInstructionTags[handlerIndex] != instructionTag) {
        ++handlerIndex;
      }
      (this->*g_apfnScenarioScriptInstructionHandlers[handlerIndex])(&instruction);
    }
  }

  delete[] buffer;
  if (g_bScenarioScriptTerminationRequested) {
    g_pAmbitApplication->PostWmCloseToMainThreadWindow();
  }

  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    nation->NameUnits();
    nation->MarkStatusFlag5HandledIfCapabilityActive();
  }

  newsEventsSuppressed = false;
  g_nSaveFormatVersion = -1;
}

// FUNCTION: IMPERIALISM 0x00582120
void TSimMgr::ScSetLabor(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int tierAToken;
  tierAToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(tierAToken);

  unsigned int tierBToken;
  tierBToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(tierBToken);

  unsigned int tierCToken;
  tierCToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(tierCToken);

  TGreatPower* nation = g_apNationStates[ownerToken];
  TCity* city = (nation != NULL) ? nation->city : NULL;
  city->productionSummary->SetPopulation(static_cast<int>(tierAToken), static_cast<int>(tierBToken),
                                         static_cast<int>(tierCToken));

  g_apNationStates[ownerToken]->RebuildNationResourceYieldCountersAndDevelopmentTargets();

  if (g_apNationStates[ownerToken]->interiorMinister != NULL) {
    g_apNationStates[ownerToken]->interiorMinister->SetCityPolicies();
  }
}

// FUNCTION: IMPERIALISM 0x005822c0
void TSimMgr::ScSetCapacity(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int indexToken;
  indexToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == NULL) {
    city = NULL;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  int index = static_cast<short>(indexToken);
  short value = static_cast<short>(valueToken);
  short* accum = &city->productionAccum[index];
  *accum = static_cast<short>(*accum + (value - city->productionOrderTable[index]));
  city->productionOrderTable[index] = value;
}

// FUNCTION: IMPERIALISM 0x005823e0
void TSimMgr::ScSetWarehouse(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int indexToken;
  indexToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == NULL) {
    city = NULL;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  city->stockByType[static_cast<short>(indexToken)] = static_cast<short>(valueToken);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x005824c0
void TSimMgr::ScAddArmy(STurnInstructionCursor* instruction) {

  unsigned int regionToken;
  regionToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(regionToken);

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int countToken;
  countToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(countToken);

  int remaining = static_cast<int>(countToken);
  int ownerNationCode =
      g_pGlobalMapState->cityScoreTable[static_cast<int>(regionToken)].ownerNationCode;
  while (remaining > 0) {
    TMilitaryUnit* order = new TMilitaryUnit();
    order->IMilitaryUnit(static_cast<short>(orderTypeToken), static_cast<int>(regionToken),
                         ownerNationCode, 0);
    order->SetOrders(static_cast<UnitOrder>(2), -1);
    --remaining;
  }
}

// FUNCTION: IMPERIALISM 0x00582630
void TSimMgr::ScAddCivilian(STurnInstructionCursor* instruction) {

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int terrainToken;
  terrainToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(terrainToken);

  int ownerNationTag =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(terrainToken)].ownerNationTag;
  TCivUnit* order = new TCivUnit();
  order->ICivUnit(static_cast<CivilianUnitKind>(orderTypeToken), terrainToken, ownerNationTag);
}

// FUNCTION: IMPERIALISM 0x00582720
void TSimMgr::ScAddShip(STurnInstructionCursor* instruction) {

  unsigned int nationToken;
  nationToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int contextToken;
  contextToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(contextToken);

  unsigned int countToken;
  countToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(countToken);

  short orderType = static_cast<short>(orderTypeToken);
  int nationSlot = static_cast<int>(nationToken);
  TZone* context = FindMapActionContextByNodeId(static_cast<short>(contextToken));
  TCity* city;
  if (g_apNationStates[nationSlot] == 0) {
    city = 0;
  } else {
    city = g_apNationStates[nationSlot]->city;
  }
  city->orderCountByType[orderType] =
      static_cast<short>(city->orderCountByType[orderType] + static_cast<short>(countToken));

  int remaining = static_cast<int>(countToken);
  while (remaining != 0) {
    CreateNavyPrimaryOrderNodeAndAssignDisplayName(orderType, context, nationSlot, 0);
    --remaining;
  }
}

// FUNCTION: IMPERIALISM 0x00582860
void TSimMgr::ScSetTransport(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  g_apNationStates[static_cast<int>(nationToken)]->transportCapacity =
      static_cast<short>(valueToken);
}

// FUNCTION: IMPERIALISM 0x005828f0
void TSimMgr::ScSetDevLevel(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int tileToken;
  tileToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(tileToken);
  short tileIndex = static_cast<short>(tileToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;

  int tileResourceKind = g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[0];
  bool selectHighNibble = false;
  if (tileResourceKind == kResourceGold || tileResourceKind == kResourceGems ||
      tileResourceKind == kResourceIron || tileResourceKind == kResourceCoal ||
      tileResourceKind == kResourceOil) {
    selectHighNibble = true;
  }
  unsigned char* valueTokenBytes = static_cast<unsigned char*>(static_cast<void*>(&valueToken));
  unsigned char value = valueTokenBytes[3];
  g_pGlobalMapState->SetDevelopmentLevel(tileIndex, selectHighNibble, value, true);
}

// FUNCTION: IMPERIALISM 0x005829b0
void TSimMgr::ScAddRailhead(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
  g_pGlobalMapState->BuildRailhead(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibility == 0) {
    g_apNationStates[nationTag]->treasuryValue += 2000;
  }
}

// FUNCTION: IMPERIALISM 0x00582a40
void TSimMgr::ScAddPort(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
  g_pGlobalMapState->BuildPort(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibility == 0) {
    g_apNationStates[nationTag]->treasuryValue += 3000;
  }
}

// FUNCTION: IMPERIALISM 0x00582ad0
void TSimMgr::ScAddTech(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int techToken;
  techToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(techToken);

  g_pTechMgr->ActivateAdvance(static_cast<int>(techToken), static_cast<int>(nationToken));
}

// FUNCTION: IMPERIALISM 0x00582b70
void TSimMgr::ScSetPrice(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int categoryToken;
  categoryToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(categoryToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  g_pTradeMgr->UpdatePrice(static_cast<short>(categoryToken), static_cast<short>(valueToken));
}

// FUNCTION: IMPERIALISM 0x00582bf0
void TSimMgr::ScSetEmbassy(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationAToken;
  nationAToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationAToken);

  unsigned int nationBToken;
  nationBToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationBToken);

  unsigned int valueToken;
  valueToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  int nationA = static_cast<int>(nationAToken);
  int nationB = static_cast<int>(nationBToken);
  short value = static_cast<short>(valueToken);
  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  diplomacy->relationSideEffectMatrix[nationA * 0x17 + nationB] = value;
  diplomacy->relationSideEffectMatrix[nationB * 0x17 + nationA] = value;
}

// FUNCTION: IMPERIALISM 0x00582ce0
void TSimMgr::ScSetSubsidy(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(targetToken);

  unsigned int levelToken;
  levelToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(levelToken);

  g_apNationStates[ownerToken]->SetTradePolicyTo(static_cast<NationSlot>(targetToken),
                                                 static_cast<int>(levelToken));
}

// FUNCTION: IMPERIALISM 0x00582da0
void TSimMgr::ScSetTreaty(STurnInstructionCursor* instruction) {

  unsigned int sourceToken;
  sourceToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(sourceToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(targetToken);

  unsigned int relationToken;
  relationToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(relationToken);

  int sourceNation = static_cast<int>(sourceToken);
  int targetNation = static_cast<int>(targetToken);
  DiplomacyRelationship relationship = static_cast<DiplomacyRelationship>(relationToken);
  g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(sourceNation, targetNation,
                                                                        relationship);
  if (relationship == kDiplomacyRelationshipJoinedEmpire) {
    TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
    short relationSideEffect = 2;
    diplomacy->relationSideEffectMatrix[sourceNation * kNationSlotCount + targetNation] =
        relationSideEffect;
    diplomacy->relationSideEffectMatrix[targetNation * kNationSlotCount + sourceNation] =
        relationSideEffect;
    g_apTerrainTypeDescriptorTable[targetNation]->BecomeColonyOf(sourceNation);
  }
}

// FUNCTION: IMPERIALISM 0x00582ed0
void TSimMgr::ScSetYear(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  economicTurn = static_cast<short>(token) * 4;
}

// FUNCTION: IMPERIALISM 0x00582f20
void TSimMgr::ScSetProvince(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int cityToken;
  cityToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(cityToken);

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(nationToken);

  g_pGlobalMapState->ChangeProvinceOwner(static_cast<short>(cityToken),
                                         static_cast<short>(nationToken));
}

// FUNCTION: IMPERIALISM 0x00582fa0
void TSimMgr::ScSetSeazoneName(STurnInstructionCursor* instruction) {

  unsigned int contextToken;
  contextToken = *instruction->tokenCursor;
  const char* rawName =
      reinterpret_cast<const char*>(instruction->tokenCursor) + sizeof(unsigned int);
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(contextToken);

  CString contextName(rawName);
  instruction->tokenCursor += 0x10;
  short contextId = static_cast<short>(contextToken);
  if (FindMapActionContextByNodeId(contextId) != 0) {
    TZone* context = FindMapActionContextByNodeId(contextId);
    context->displayName = contextName;
  }
}

// Source evidence: retail constructs and destroys three unused CString locals.
// FUNCTION: IMPERIALISM 0x00583070
void TSimMgr::ScSetCountryName(STurnInstructionCursor* instruction) {

  unsigned int countryToken;
  countryToken = *instruction->tokenCursor;
  const char* rawName =
      reinterpret_cast<const char*>(instruction->tokenCursor) + sizeof(unsigned int);
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(countryToken);

  CString countryName(rawName);
  instruction->tokenCursor += 0x10;
  CString unusedNamePartA;
  CString unusedNamePartB;
  CString unusedNamePartC;

  int countryIndex = static_cast<int>(countryToken);
  g_apTerrainTypeDescriptorTable[countryIndex]->SetNationDisplayNameAndLocalizationSlotRef(
      countryName);
  g_apTerrainTypeDescriptorTable[countryIndex]->identitySharedString1 = countryName;
}

// FUNCTION: IMPERIALISM 0x005831d0
void TSimMgr::ScSetRelationship(STurnInstructionCursor* instruction) {

  unsigned int sourceToken;
  sourceToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(sourceToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(targetToken);

  unsigned int scoreToken;
  scoreToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_SHORT_TOKEN(scoreToken);

  g_pDiplomacyTurnStateManager->SetRelationship(sourceToken, targetToken, scoreToken);
}

// FUNCTION: IMPERIALISM 0x00583270
void TSimMgr::ScSetProvinceName(STurnInstructionCursor* instruction) {

  unsigned int tileToken;
  tileToken = *instruction->tokenCursor;
  const char* rawName =
      reinterpret_cast<const char*>(instruction->tokenCursor) + sizeof(unsigned int);
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(tileToken);

  CString rawText(rawName);
  instruction->tokenCursor += 0x10;
  CString name(rawText);
  g_pGlobalMapState->SetProvinceName(static_cast<int>(tileToken), &name);
}

// FUNCTION: IMPERIALISM 0x00583360
void TSimMgr::ScSetTreasury(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int cashToken;
  cashToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(cashToken);

  g_apNationStates[static_cast<int>(nationToken)]->treasuryValue = static_cast<int>(cashToken);
}

// FUNCTION: IMPERIALISM 0x00583400
void TSimMgr::ScSetFlags(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short index = static_cast<short>(token);
  mapArtSet = index;
  g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(index);
  g_pMacViewMgr->ReloadMapArtAtlases();
}

// FUNCTION: IMPERIALISM 0x00583470
void TSimMgr::ScSetTechDate(STurnInstructionCursor* instruction) {

  unsigned int indexToken;
  indexToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(valueToken);

  g_pTechMgr->SetAdvanceDate(static_cast<int>(indexToken), static_cast<int>(valueToken + 1));
}

// FUNCTION: IMPERIALISM 0x00583510
void TSimMgr::ScSetTransportBar(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int typeToken;
  typeToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(typeToken);

  unsigned int valueToken;
  valueToken = *instruction->tokenCursor;
  ++instruction->tokenCursor;
  DECODE_SCENARIO_DWORD_TOKEN(valueToken);

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

// FUNCTION: IMPERIALISM 0x00583670
void TSimMgr::ScClearTransport(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int nationToken;
  nationToken = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);
  int nation = static_cast<int>(nationToken);

  g_apNationStates[nation]->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  for (int needIndex = 0; needIndex < 0x17; ++needIndex) {
    g_apNationStates[nation]->UpdateNeedTargetAndAccumulateOverCap(static_cast<short>(needIndex),
                                                                   0);
  }
}

// FUNCTION: IMPERIALISM 0x00583700
void TSimMgr::ScSetCouncilMeeting(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int slotToken;
  slotToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(slotToken);

  unsigned int stateToken;
  stateToken = *cursor;
  ++cursor;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(stateToken);

  int slot = static_cast<int>(slotToken);
  councilByDecade[slot] = static_cast<unsigned char>(stateToken);
  if (stateToken == 2) {
    finalCouncilYear = static_cast<short>(static_cast<short>(slotToken) * 10 + 0x717);
  }
}

#undef DECODE_SCENARIO_SHORT_TOKEN
#undef DECODE_SCENARIO_DWORD_TOKEN

// FUNCTION: IMPERIALISM 0x005837c0
void TSimMgr::SetPlayerCountry(NationSlot nationSlot) {
  activeNationSlot = nationSlot;
  g_pMacViewMgr->RefreshCityCapabilityUiHandlesForActiveNation();
}

// FUNCTION: IMPERIALISM 0x005d4c10
unsigned char __cdecl TryGetFileMetadataForPath(CString* path) {
  CFileStatus status;
  // Callers branch on AL: the original returns a Mac-style byte Boolean, not BOOL.
  return static_cast<unsigned char>(CFile::GetStatus(*path, status));
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
