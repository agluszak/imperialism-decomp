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
#define TSIMMGR_LAYOUT_ASSERT(name, expr) typedef char name[(expr) ? 1 : -1]
TSIMMGR_LAYOUT_ASSERT(TSimMgr_Offset_economicTurn_0x2C, offsetof(TSimMgr, economicTurn) == 0x2C);
TSIMMGR_LAYOUT_ASSERT(TSimMgr_Offset_activeNationSlot_0x2E,
                      offsetof(TSimMgr, activeNationSlot) == 0x2E);
TSIMMGR_LAYOUT_ASSERT(TSimMgr_Offset_numGreatPowers_0x30,
                      offsetof(TSimMgr, numGreatPowers) == 0x30);
TSIMMGR_LAYOUT_ASSERT(TSimMgr_Offset_numMinorCountries_0x34,
                      offsetof(TSimMgr, numMinorCountries) == 0x34);
TSIMMGR_LAYOUT_ASSERT(TSimMgr_Offset_turnFlowStatusFlags_0x3C,
                      offsetof(TSimMgr, turnFlowStatusFlags) == 0x3C);

void RegenerateAllMapActionContextStatusCodes();

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

IMPLEMENT_DYNCREATE(TSimMgr, TObject)

// FUNCTION: IMPERIALISM 0x0057b9e0
TSimMgr::TSimMgr() : sharedTextSlots() {
  turnStateCode = kGamePhaseStartup;
  mode = kGamePhaseStartup;
  previousTurnStateCode = kGamePhaseStartup;
  previousMode = kGamePhaseStartup;
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
  field_64 = 0;
  councilByDecade[0] = 0;
  // Ten bytes 0x6f..0x78 (councilByDecade[1..9] + field78) are filled with 1 in one
  // pass (dword/dword/word stores in the original); field78 is then overwritten with 2.
  memset(&councilByDecade[1], 0x01, sizeof(councilByDecade));
  field79 = true;
  field78 = 2;
  // Developer-cheat probe: stat a file literally named "Conan" in the working directory;
  // the original discards the result and clears the cheat flag unconditionally (the flag
  // is armed elsewhere).
  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = false;
  ReinitializeRandomSeed();
  difficultyLevel = kDifficultyIntroductory;
  UpdatePreferences(false);
  field6a = 0;
  finalCouncilYear = 0x77a;
  gateFlag7a = false;
}

// FUNCTION: IMPERIALISM 0x0057bc90
void TSimMgr::ResetTurnFlowStateAndRandomSeed() {
  economicTurn = 0;
  activeNationSlot = -1;
  field14 = 0;
  turnStateCode = kGamePhaseStartup;
  turnFlowStatusFlags = 0;
  field_64 = 0;
  councilByDecade[0] = 0;
  councilByDecade[1] = 1;
  councilByDecade[2] = 1;
  councilByDecade[3] = 1;
  councilByDecade[4] = 1;
  councilByDecade[5] = 1;
  councilByDecade[6] = 1;
  councilByDecade[7] = 1;
  councilByDecade[8] = 1;
  councilByDecade[9] = 1;
  field79 = true;
  field78 = 2;

  CFileStatus conanFileStatus;
  CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
  g_bRandomMapDeveloperCheatFlag = false;
  ReinitializeRandomSeed();
}

// FUNCTION: IMPERIALISM 0x0057bd20
void TSimMgr::Free() {
  int i;
  if (g_pTradeMgr != nullptr) {
    g_pTradeMgr->Free();
    g_pTradeMgr = nullptr;
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
  if (g_pTechMgr != nullptr) {
    g_pTechMgr->Free();
    g_pTechMgr = nullptr;
  }
  if (g_pNewsMgr != nullptr) {
    g_pNewsMgr->Free();
    g_pNewsMgr = nullptr;
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
    difficultyLevel = static_cast<eDifficulty>(stream->ReadByte() & 0xff);
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

  // The persisted role is retained only for stream compatibility.  The load path
  // continues to use the current session role when deciding whether game-flow data
  // is present.
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
    field6a = selectedIndex;
    g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(selectedIndex);
  } else {
    field6a = (scenarioMapIndexPlusOne != 0) ? 1 : 0;
    g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(field6a);
  }

  g_pMacViewMgr->ReloadBitmap244AndRefreshUiCaches();

  if (g_nSaveFormatVersion >= 0x36) {
    stream->ReadBytes(&finalCouncilYear, 2);
  }

  if (g_nSaveFormatVersion < 0x3b) {
    memset(councilByDecade, 0x01, sizeof(councilByDecade));
    field79 = true;
    councilByDecade[0] = 0;
    councilByDecade[(finalCouncilYear - 0x717) / 10] = 2;
  } else {
    stream->ReadBytes(councilByDecade, 0xc);
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
  CreatePlanet(0, nullptr, 0);
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
  stream->WriteBytes(&field_64, 4);
  stream->WriteBytes(&field15, 0x17);
  stream->WriteBytes(&multiplayerSessionRole, 4);

  bool hasGameFlowState = multiplayerSessionRole != kSessionRoleStandalone;
  if (hasGameFlowState) {
    g_pGameFlowState->WriteTo(stream);
  }

  stream->WriteBytes(&preferenceValues[10], 2);
  stream->WriteBytes(&field6a, 2);
  stream->WriteBytes(&finalCouncilYear, 2);
  stream->WriteBytes(councilByDecade, 0xc);

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
    animator->IAnimator(0x7fffffff);
    animator->Install();
    g_pUiAnimator = animator;

    if (g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->Free();
      g_pDiplomacyTurnStateManager = nullptr;
    }
    TDiplomacyMgr* diplomacyManager = new TDiplomacyMgr();
    diplomacyManager->InitializeTDiplomacyTurnStateManagerDefaults();
    g_pDiplomacyTurnStateManager = diplomacyManager;

    if (g_pTradeMgr != nullptr) {
      g_pTradeMgr->Free();
      g_pTradeMgr = nullptr;
    }
    TTradeMgr* tradeManager = new TTradeMgr();
    tradeManager->ITradeMgr();
    g_pTradeMgr = tradeManager;

    if (g_pNewsMgr != nullptr) {
      g_pNewsMgr->Free();
      g_pNewsMgr = nullptr;
    }
    TNewsMgr* newsManager = new TNewsMgr();
    newsManager->InitializeNewsManager();
    g_pNewsMgr = newsManager;

    if (g_pMapContextActionManager != nullptr) {
      g_pMapContextActionManager->Free();
      g_pMapContextActionManager = nullptr;
    }
    TArmyMgr* armyManager = new TArmyMgr();
    armyManager->IArmyMgr();
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

    if (g_pTechMgr != nullptr) {
      g_pTechMgr->Free();
    }
    g_pTechMgr = new TTechMgr();
    g_pTechMgr->InitializeCityOrderCapabilityStateDefaults();
  }
}

// FUNCTION: IMPERIALISM 0x0057c7c0
void TSimMgr::CreatePlanet(int arg1, const char* arg2, int arg3) {
  int i;
  if (!g_bMultiplayerScenarioSetupActive) {
    CString local_10;
    for (i = 0; i < 0x17; ++i) {
      SetSharedStringFromMappedFlavorTextWithLengthClamp(&local_10, i);
      sharedTextSlots[i] = local_10;
    }
  }

  char rebuildFlag = static_cast<char>(arg1);
  if (((rebuildFlag != 0) && (!g_bMultiplayerScenarioSetupActive)) ||
      ((rebuildFlag == 0) && (g_bMultiplayerScenarioSetupActive))) {
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
    g_pGlobalMapState->IMapMgr();

    if (!g_bMultiplayerScenarioSetupActive) {
      g_pGlobalMapState->hexNeighborWrapHorizontally = static_cast<char>(arg3);
      g_pGlobalMapState->BuildOrLoadGlobalMapStateForSession(nullptr, const_cast<char*>(arg2));
    } else {
      g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057c9a0
unsigned char TSimMgr::LoadScenario(int scenarioIndex) {
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
  g_pGlobalMapState->IMapMgr();
  g_pGlobalMapState->hexNeighborWrapHorizontally = 1;
  return static_cast<unsigned char>(
      g_pGlobalMapState->BuildOrLoadGlobalMapStateForSession(g_szEmptyString, g_szEmptyString));
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

  if (!g_bMultiplayerScenarioSetupActive) {
    g_pDiplomacyTurnStateManager->RebuildCivilianOrderCompatibilityMatrices();
    g_pViewMgr->RebuildMapTileNeighborHighlightPolygonsForAllTiles();
    g_pTechMgr->GenerateRandomCapabilityPrioritySlots();
    g_pGlobalMapState->GenerateProvinceNames();
    RegenerateAllMapActionContextStatusCodes();
    g_pNewsMgr->AddMiscEvent(999, 1, true);
    g_pNewsMgr->AddMiscEvent(999, 2, true);

    const char* tagText = g_pGlobalMapState->scenarioTagText;
    if (tagText[0] == '.') {
      CString path;
      path.Format(s_PictWvGobPathFormat_00698BF4, tagText[1] - '0');
      if (TryGetFileMetadataForPath(&path)) {
        g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(tagText[1] - '0');
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
        TCity* city = nationState != nullptr ? nationState->city : nullptr;
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
      TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
      pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
    }
  } else if (setupMode == 3) {
    TGreatPower* pTVar5 = (TGreatPower*)new TProxyGreatPower();
    pTVar5->IGreatPower(slotIndex, 1);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (!g_bMultiplayerScenarioSetupActive) {
      if (activate != 0) {
        TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
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
    // Real allocation is operator_new(0xb70) followed by TAutoGreatPower::TAutoGreatPower()
    // (ctor thunk 0x407a31 -> 0x4e6b50) -- this slot is genuinely a TAutoGreatPower, not a
    // bare TGreatPower (whose object size is 0x964, too small for the tail AI state block).
    TAutoGreatPower* pTVar5 = new TAutoGreatPower();
    pTVar5->IAutoGreatPower(slotIndex, 2, cityMinisterPolicyIds[nationIndex],
                            foreignMinisterPolicyIds[nationIndex],
                            defenseMinisterPolicyIds[nationIndex]);
    g_apNationStates[nationIndex] = pTVar5;
    g_apTerrainTypeDescriptorTable[nationIndex] = pTVar5;

    if (!g_bMultiplayerScenarioSetupActive) {
      if (activate != 0) {
        TCity* city = pTVar5 != nullptr ? pTVar5->city : nullptr;
        pTVar5->ApplyScenarioRelationPresetAndSpawnFrogCity(city);
      }
      pTVar5->QueueMapActionMissionsForPortZoneCandidates();
      pTVar5->NameUnits();
    }
  } else {
    g_apNationStates[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;
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
  if (nationIndex < numMinorCountries + 7 && multiplayerSessionRole == kSessionRoleClient) {
    if (g_apSecondaryNationStateSlots[nationIndex] != nullptr) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;
    minor = new TRemoteMinor();
    minor->IMinor(static_cast<NationSlot>(slotIndex));
  } else if (nationIndex < numMinorCountries + 7) {
    if (g_apSecondaryNationStateSlots[nationIndex] != nullptr) {
      g_apSecondaryNationStateSlots[nationIndex]->Free();
    }
    g_apSecondaryNationStateSlots[nationIndex] = nullptr;
    g_apTerrainTypeDescriptorTable[nationIndex] = nullptr;

    minor = new TMinor();
    minor->IMinor(static_cast<NationSlot>(slotIndex));

    g_apSecondaryNationStateSlots[nationIndex] = minor;
    g_apTerrainTypeDescriptorTable[nationIndex] = minor;

    if (!g_bMultiplayerScenarioSetupActive) {
      minor->InitialMilitia();

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

      minor->NameUnits();
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

// FUNCTION: IMPERIALISM 0x0057d7a0
void TSimMgr::DoPerTurnMissionAIStuff(int replanMode) {
  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  RecomputeNationOrderPriorityMetrics();

  short nationSlot = 0;
  TGreatPower** nation = g_apNationStates;
  do {
    if (nationSlot != -1) {
      TCountry* country = g_apTerrainTypeDescriptorTable[nationSlot];
      if (country != nullptr && (nationSlot >= 7 || country->encodedNationSlot < 100 ||
                                 country->encodedNationSlot >= 200)) {
        (*nation)->RefreshTrackedEntriesAndReplanAiDevelopment(replanMode);
      }
    }
    ++nation;
    ++nationSlot;
  } while (nation < &g_apNationStates[7]);
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

  if (turnStateCode == kGamePhaseAdvanceSeason && g_nTurnCooldownDeferCounter006A43C4 > 0) {
    --g_nTurnCooldownDeferCounter006A43C4;
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
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      nation->AssertValid();
      if (!nation->IsRemote() && !g_bMultiplayerScenarioSetupActive) {
        nation->SetHomeCityTileAndDisplayName(-1, 0);
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
    activeNation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    activeNation->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
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
      g_pSimMgr->CreatePlanet(1, s_Chunk_00698C0C, 1);
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
      if (activeNationSlot == -1 || g_apTerrainTypeDescriptorTable[activeNationSlot] == nullptr ||
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
      if (g_pViewMgr->ModalMessage(message, g_ptTurnTransitionModalMessage, 1, 1) == 0) {
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
      for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != nullptr && nation->diplomacyEligibility != 0 &&
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
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ReplyToDiplomacyOffers();
      }
    }
    if (multiplayerSessionRole == kSessionRoleStandalone ||
        (multiplayerSessionRole == kSessionRoleHost &&
         !IsNationEligibleForOptionalPhase(activeNationSlot))) {
      // 0x57df05: new TNextDiplomationCommand() + immediate dispatch; the original
      // calls the method even when operator new returned null (kept faithfully).
      TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
      nextCommand->DispatchUiPacketWithTagNEXT();
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
    // For each live nation slot 6..0, slot 0xaf (the pressure-state update, byte 0x2bc)
    // returns a char: when set, fire the active nation's no-payload turn-event dispatch
    // (slot 0xab, byte 0x2ac). The original derefs the active nation's vtable with no
    // null guard here, so this stays a direct virtual call.
    for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr) {
        continue;
      }
      if (nation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage() == 0) {
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
    // Verified against 0x0057e487: real receiver is g_pMapContextActionManager (no null
    // guard on it, matching the missing-guard pattern used elsewhere in this switch).
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
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      g_apNationStates[nationSlot]->MarkAllPendingStatusFlagsHandled();
    }
    bool saveTurn = false;
    if (g_nTurnCooldownDeferCounter006A43C4 < 1) {
      g_nTurnCooldownDeferCounter006A43C4 = 0;
      g_nTurnCooldownSideFlag00698B10 = 1;
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
        g_pGameFlowState->TrySaveGameAndMaybeShowFailureDialog(0xa1, 0, true);
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
    const short capabilityBefore = g_pTechMgr != nullptr ? g_pTechMgr->marker262 : 0;
    g_pTechMgr->CheckForAdvances();
    if (capabilityBefore == (g_pTechMgr != nullptr ? g_pTechMgr->marker262 : 0)) {
      turnFlowStatusFlags |= 0x40;
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (g_pSimMgr->activeNationSlot == nationSlot && g_nTurnCooldownDeferCounter006A43C4 < 1) {
        g_nTurnCooldownDeferCounter006A43C4 = 0;
        g_nTurnCooldownSideFlag00698B10 = 1;
        if (IsNationEligibleForOptionalPhase(activeNationSlot)) {
          short unlockSlot =
              g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
          if (unlockSlot != -1) {
            g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTechnologyAdvance),
                                          unlockSlot);
            actionNeeded = false;
          }
          continue;
        }
      }
      short unlockSlot =
          g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
      while (unlockSlot != -1) {
        unlockSlot = g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
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
    g_pGlobalMapState->DispatchTurnEvent7DDForActiveNation();
    g_pViewMgr->RefreshViewSlot48();
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr || nationSlot == -1) {
        continue;
      }
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      nation->InitializeDiplomacyNotices();
      nation->DisplayTurnStartEvents();
    }
    g_pSfxPlaybackSystem->ResetDualAudioCuePools();
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(2);
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(3);
    g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
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
      for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
        if (nationSlot == -1 || g_apTerrainTypeDescriptorTable[nationSlot] == nullptr) {
          continue;
        }
        // Verified against 0x0057e0b7: real receiver is g_apTerrainTypeDescriptorTable[nationSlot]
        // (a TCountry*), not a bare free-function predicate.
        if (nationSlot < 7 &&
            g_apTerrainTypeDescriptorTable[nationSlot]->IsNationProfileInMinorRange100To199()) {
          continue;
        }
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != nullptr) {
          nation->RefreshTrackedEntriesAndReplanAiDevelopment(0);
        }
      }
    }
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationEligibleForOptionalPhase(nationSlot)) {
        continue;
      }
      g_apNationStates[nationSlot]->AddPurchasedItems();
    }
    const short tickA = GetEconomicTurn();
    const short tickB = GetEconomicTurn();
    if (((tickB % 0x28) == 0) && (councilByDecade[tickA / 0x28] != 0) &&
        multiplayerSessionRole != kSessionRoleClient) {
      g_pDiplomacyTurnStateManager->RebuildDiplomacyStandingAndInfluenceMatrices(
          councilByDecade[tickA / 0x28]);
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
    // Verified against 0x0057e1be: the original reads g_pSimMgr->activeNationSlot with no
    // null guard, and when the localization nation's encoded slot is in [100,200) it fires
    // the active nation's no-payload turn-event dispatch (slot 0xab, byte 0x2ac) with no
    // arg and no null check on the active nation.
    {
      const short localizationNation = g_pSimMgr->activeNationSlot;
      TGreatPower* localizationNationState = g_apNationStates[localizationNation];
      if (localizationNationState != nullptr) {
        const short encoded = localizationNationState->encodedNationSlot;
        if (encoded > 99 && encoded < 200) {
          TGreatPower* activeNation = g_apNationStates[activeNationSlot];
          activeNation->SorryYouLose();
          actionNeeded = true;
        }
      }
    }
    for (int removeNationSlot = 0; removeNationSlot < 7; ++removeNationSlot) {
      if (g_apTerrainTypeDescriptorTable[removeNationSlot] == nullptr ||
          g_apNationStates[removeNationSlot] == nullptr) {
        continue;
      }
      if (g_apNationStates[removeNationSlot]->ownedRegionList->GetSize() == 0) {
        EliminateGP(static_cast<short>(removeNationSlot));
      }
    }
    for (int secondaryIndex = 7; secondaryIndex < 0x17; ++secondaryIndex) {
      TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
      if (secondaryNation != nullptr && secondaryNation->ownedRegionList->GetSize() == 0) {
        for (short percentNationSlot = 0; percentNationSlot < 7; ++percentNationSlot) {
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
    for (int countNationSlot = 0; countNationSlot < 7; ++countNationSlot) {
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

  // Jump-table ground truth (0x57dad8, index-byte table 0x57ebec): case 0x71 -> 0x57eabf
  // (posts 0x104f), case 0x72 -> 0x57ead8 (posts 0x5e4). The old merged port dropped both
  // event codes.
  case kGamePhaseOptionalCredits:
    turnStateCode = kGamePhaseShowMap;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventCredits));
    break;

  case kGamePhaseOptionalNetworkGameOptions:
    turnStateCode = kGamePhaseShowMap;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(
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
    g_pAmbitApplication->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventGamePreferences));
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
char TSimMgr::InLinearPhase() {
  eGamePhaseNewStyle phase = turnStateCode;
  bool linear = (phase < kGamePhaseShowMap) || (phase > kGamePhaseEndTurn);
  return linear;
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

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (!IsNationEligibleForOptionalPhase(static_cast<short>(nationSlot))) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationSlot];
    nation->PayForMilitary();
    nation->SelectAndQueueAdvisoryMapMissionsCase16();
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
  g_pTradeMgr->RunNationUpdatePassesAndResetTransitionFlags();
  g_pTradeMgr->SetMinorsTradeBids();
  g_pTradeMgr->TallyTradeBids();
  g_pTradeMgr->CalculateNewWorldPrices();
  g_pTradeMgr->CalculateDealOrder();

  int shouldSendTradeBook = multiplayerSessionRole != kSessionRoleStandalone;
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

// Out-of-line in the original: every callsite (ShowTurnAlertsForActiveNation x3,
// ShowTerrainMap x8) calls this copy instead of inlining the mask test.
// FUNCTION: IMPERIALISM 0x0057f4d0
unsigned char TSimMgr::TestTurnFlowStatusFlagMask(unsigned int mask) {
  // test+setne needs the branchy if/return-1/return-0 shape (VC5 folds it to a byte
  // set); every value-form spelling (`!= 0`, bool, ternary) emits neg/sbb/neg instead.
  if (mask & turnFlowStatusFlags) {
    return 1;
  }
  return 0;
}

// MATCH: retail leaves upper EAX dirty (char return); residual is VC5's signed
// pointer-compare (jl) on the array-end bound, same as DoPerTurnMissionAIStuff.
// FUNCTION: IMPERIALISM 0x0057f4f0
char TSimMgr::AllHumansFinished() {
  bool finished = true;
  for (TGreatPower** nation = g_apNationStates; nation < g_apNationStates + 7; ++nation) {
    if ((*nation)->field904 == 0) {
      finished = false;
      break;
    }
  }
  return finished;
}

// FUNCTION: IMPERIALISM 0x0057f530
void TSimMgr::ResetTurnFlags() {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation->diplomacyEligibility != 0) {
      nation->field904 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057f570
void TSimMgr::PrepareMultiplayerTurnResume() {
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
void TSimMgr::GetStringPrelude(short offset, CString* destString) {
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

  // Ground truth (0x5807fa..0x580821) zeroes `rejected` first, then loads BOTH
  // notice fields into registers before the sign test, and only sign-flips `code`
  // afterwards -- so nationSlot is read ahead of the branch, not at its use site.
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
    g_pSimMgr->GetStringPrelude(code, &commodityName);
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
char TSimMgr::ReallyInTheGame(NationSlot nationSlot) {
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
      bool inReservedProfileBand = profileType >= 100 && profileType < 200;
      if (inReservedProfileBand) {
        return 0;
      }
    }
  }

  return 1;
}

// FUNCTION: IMPERIALISM 0x00581300
void TSimMgr::EliminateGP(NationSlot nationSlot) {
  // Neutralize the removed nation's diplomacy percent field on every other live slot. For
  // the seven great-power slots a nation whose terrain profile is in the reserved band
  // [100,200) is left alone; minor slots (i >= 7) and unreserved great powers are reset.
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
  field15[nationSlot] = 0;
  --numGreatPowers;
  g_pDiplomacyTurnStateManager->RemoveNationSlotAndNotifyPeers_Impl(nationSlot);
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
  FILE* file = fopen(path, g_szLiteralRb_00698720);

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

    FILE* writeFile = fopen(path, g_szLiteralWb_006976E0);
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
    g_pHelpMgr->HandlePendingEventActivationByCode(kTurnEventMainMenu);
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
    simMgr->field_64 = 0;
    simMgr->councilByDecade[0] = 0;
    memset(&simMgr->councilByDecade[1], 0x01, sizeof(simMgr->councilByDecade));
    simMgr->field79 = true;
    simMgr->field78 = 2;
    CFileStatus conanFileStatus;
    CFile::GetStatus(g_szConanCheatFileName_00698BEC, conanFileStatus);
    g_bRandomMapDeveloperCheatFlag = false;
    simMgr->ReinitializeRandomSeed();
    g_pSimMgr->turnStateCode = kGamePhaseSetUpMap;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(EncodeTurnEventCode(eventCode));
  } else {
    g_pSimMgr->Free();
    g_pSimMgr = new TSimMgr();
    g_pSimMgr->ISimMgr();
    g_pSimMgr->StartNextPhase();
    if (eventCode != 0) {
      g_pAmbitApplication->PostTurnEventCodeMessage2420(EncodeTurnEventCode(eventCode));
    }
  }
  g_bTurnFlowBootstrapComplete = true;
}

// FUNCTION: IMPERIALISM 0x00581ae0
void TSimMgr::SetSelectedIndex6AAndTriggerRefresh(short index) {
  field6a = index;
  g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(index);
  g_pMacViewMgr->ReloadBitmap244AndRefreshUiCaches();
}

// FUNCTION: IMPERIALISM 0x00581b20
CString TSimMgr::LoadNormalizedCredentialName(short slot) {
  CString name = g_pLanguageMgr->StripCodeStr(sharedTextSlots[slot]);
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

    const short cityRecordIndex = static_cast<short>(country->GetCapitolProvince());
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
  gateFlag7a = true;
  g_nSaveFormatVersion = -3;
  g_bScenarioScriptTerminationRequested = false;
  g_nScenarioScriptInstructionCount = 0;

  g_pAssetMgr->BuildScenarioPathForModeAndIndex(static_cast<short>(scenarioMapIndexPlusOne) - 1, 2,
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
    instruction.tokenCursor = instruction.tokenCursor + 1;
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

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    nation->NameUnits();
    nation->MarkStatusFlag5HandledIfCapabilityActive();
  }

  gateFlag7a = false;
  g_nSaveFormatVersion = -1;
}

// Reads a big-endian 32-bit nation index and three big-endian 16-bit tokens (three labor
// tier counts). Applies them to the nation's city population summary (baseline/production
// tier buckets, need totals), kicks off a resource-yield rebuild, and notifies the nation's
// defense minister (if any) via its slot-0x14 hook.
// FUNCTION: IMPERIALISM 0x00582120
void TSimMgr::ScSetLabor(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int tierAToken;
  tierAToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(tierAToken);

  unsigned int tierBToken;
  tierBToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(tierBToken);

  unsigned int tierCToken;
  tierCToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(tierCToken);

  TGreatPower* nation = g_apNationStates[ownerToken];
  TCity* city = (nation != nullptr) ? nation->city : nullptr;
  city->productionSummary->SetPopulation(static_cast<int>(tierAToken), static_cast<int>(tierBToken),
                                         static_cast<int>(tierCToken));

  g_apNationStates[ownerToken]->RebuildNationResourceYieldCountersAndDevelopmentTargets();

  if (g_apNationStates[ownerToken]->interiorMinister != nullptr) {
    g_apNationStates[ownerToken]->interiorMinister->SetCityPolicies();
  }
}

// Reads a big-endian 32-bit nation slot, a big-endian short production-order index, and a
// big-endian short value; sets that nation's capital-city production-order slot to the
// value while accumulating the delta (value - old) into the parallel running-total slot.
// FUNCTION: IMPERIALISM 0x005822c0
void TSimMgr::ScSetCapacity(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int indexToken;
  indexToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == nullptr) {
    city = nullptr;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  int index = static_cast<short>(indexToken);
  short value = static_cast<short>(valueToken);
  short* accum = &city->productionAccum[index];
  *accum = static_cast<short>(*accum + (value - city->productionOrderTable1dc[index]));
  city->productionOrderTable1dc[index] = value;
}

// Reads a big-endian 32-bit nation slot, a big-endian short commodity index, and a
// big-endian short amount; writes the amount into that nation's capital-city commodity
// stock counter and re-verifies the city's stock invariants.
// FUNCTION: IMPERIALISM 0x005823e0
void TSimMgr::ScSetWarehouse(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int indexToken;
  indexToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  TCity* city;
  if (g_apNationStates[static_cast<int>(nationToken)] == nullptr) {
    city = nullptr;
  } else {
    city = g_apNationStates[static_cast<int>(nationToken)]->city;
  }
  (&city->cityStockCotton)[static_cast<short>(indexToken)] = static_cast<short>(valueToken);
  city->VerifyStocks();
}

// Reads a region index, a recruit-order type, and a repeat count. The region owner is
// taken from the map-state city-score row; each requested order is registered there and
// put into order mode 2 with the original -1 payload.
// FUNCTION: IMPERIALISM 0x005824c0
void TSimMgr::ScAddArmy(STurnInstructionCursor* instruction) {

  unsigned int regionToken;
  regionToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(regionToken);

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int countToken;
  countToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(countToken);

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

// FUNCTION: IMPERIALISM 0x00582630
void TSimMgr::ScAddCivilian(STurnInstructionCursor* instruction) {

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int terrainToken;
  terrainToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(terrainToken);

  int ownerNationTag =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(terrainToken)].ownerNationTag04;
  TCivUnit* order = new TCivUnit();
  order->ICivUnit(static_cast<CivilianUnitKind>(orderTypeToken), terrainToken, ownerNationTag);
}

// Reads nation, navy-order type, map-action-context id, and count. It updates the
// nation's parallel city count then creates that many primary navy-order nodes.
// FUNCTION: IMPERIALISM 0x00582720
void TSimMgr::ScAddShip(STurnInstructionCursor* instruction) {

  unsigned int nationToken;
  nationToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int orderTypeToken;
  orderTypeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(orderTypeToken);

  unsigned int contextToken;
  contextToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(contextToken);

  unsigned int countToken;
  countToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
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
  city->orderCountByType5c[orderType] =
      static_cast<short>(city->orderCountByType5c[orderType] + static_cast<short>(countToken));

  int remaining = static_cast<int>(countToken);
  while (remaining != 0) {
    CreateNavyPrimaryOrderNodeAndAssignDisplayName(orderType, context, nationSlot, 0);
    --remaining;
  }
}

// Reads a big-endian 32-bit nation slot then a big-endian short transport-capacity value,
// stored into that nation's transportCapacity field.
// FUNCTION: IMPERIALISM 0x00582860
void TSimMgr::ScSetTransport(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  g_apNationStates[static_cast<int>(nationToken)]->transportCapacity =
      static_cast<short>(valueToken);
}

// Reads a big-endian short tile index and a development value byte, then sets that tile's
// civilian development-class nibble -- selecting the high nibble only when the tile's
// resource/edge byte is one of the qualifying terrain codes.
// FUNCTION: IMPERIALISM 0x005828f0
void TSimMgr::ScSetDevLevel(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int tileToken;
  tileToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(tileToken);
  short tileIndex = static_cast<short>(tileToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
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
  g_pGlobalMapState->SetCivilianDevelopmentClassNibble(tileIndex, selectHighNibble, value, true);
}

// Reads one big-endian short tile index, resolves that tile's owner nation, queues a depot
// construction order there, and grants the owner a 2000 cash bonus when it is not
// diplomacy-eligible.
// FUNCTION: IMPERIALISM 0x005829b0
void TSimMgr::ScAddRailhead(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  g_pGlobalMapState->QueueDepotConstructionOrder(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibility == 0) {
    g_apNationStates[nationTag]->treasuryValue10 += 2000;
  }
}

// Reads one big-endian short tile index, resolves that tile's owner nation, queues a port
// construction order there, and grants the owner a 3000 cash bonus when it is not
// diplomacy-eligible.
// FUNCTION: IMPERIALISM 0x00582a40
void TSimMgr::ScAddPort(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short tileIndex = static_cast<short>(token);
  int nationTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  g_pGlobalMapState->QueuePortConstructionOrder(tileIndex, static_cast<short>(nationTag));
  if (g_apNationStates[nationTag]->diplomacyEligibility == 0) {
    g_apNationStates[nationTag]->treasuryValue10 += 3000;
  }
}

// Reads two big-endian 32-bit tokens (forced nation slot, then tech id) and applies the
// tech unlock via the city-order capability state singleton.
// FUNCTION: IMPERIALISM 0x00582ad0
void TSimMgr::ScAddTech(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int techToken;
  techToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(techToken);

  g_pTechMgr->ApplyTechUnlockAndQueueNationAbilityNotices(static_cast<int>(techToken),
                                                          static_cast<int>(nationToken));
}

// Reads two big-endian 16-bit tokens (metric category, then value) and applies the value
// via the trade manager's per-nation metric cell setter.
// FUNCTION: IMPERIALISM 0x00582b70
void TSimMgr::ScSetPrice(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int categoryToken;
  categoryToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(categoryToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  g_pTradeMgr->UpdatePrice(static_cast<short>(categoryToken), static_cast<short>(valueToken));
}

// Reads two big-endian 32-bit nation slots and a big-endian short relation value, then
// writes the value symmetrically into both [A][B] and [B][A] of the diplomacy manager's
// side-effect relation matrix.
// FUNCTION: IMPERIALISM 0x00582bf0
void TSimMgr::ScSetEmbassy(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationAToken;
  nationAToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationAToken);

  unsigned int nationBToken;
  nationBToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationBToken);

  unsigned int valueToken;
  valueToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(valueToken);

  int nationA = static_cast<int>(nationAToken);
  int nationB = static_cast<int>(nationBToken);
  short value = static_cast<short>(valueToken);
  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  diplomacy->relationSideEffectMatrix[nationA * 0x17 + nationB] = value;
  diplomacy->relationSideEffectMatrix[nationB * 0x17 + nationA] = value;
}

// Reads a big-endian 32-bit owner-nation index plus two big-endian 16-bit tokens (target
// nation slot, then reset level) and applies them via the owner's diplomacy-level resetter.
// FUNCTION: IMPERIALISM 0x00582ce0
void TSimMgr::ScSetSubsidy(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(targetToken);

  unsigned int levelToken;
  levelToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(levelToken);

  g_apNationStates[ownerToken]->SetTradePolicyTo(static_cast<NationSlot>(targetToken),
                                                 static_cast<int>(levelToken));
}

// Reads source nation, target nation, and relation code, applies the diplomacy entry,
// and performs the symmetric relation-side-effect update used by code 5.
// FUNCTION: IMPERIALISM 0x00582da0
void TSimMgr::ScSetTreaty(STurnInstructionCursor* instruction) {

  unsigned int sourceToken;
  sourceToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(sourceToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(targetToken);

  unsigned int relationToken;
  relationToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
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

// Reads one big-endian short token (the scenario year) and stores it, scaled to quarter
// ticks (year * 4), into the turn-flow tick field at +0x2c.
// FUNCTION: IMPERIALISM 0x00582ed0
void TSimMgr::ScSetYear(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  economicTurn = static_cast<short>(token) * 4;
}

// Reads a big-endian short city-record index and a big-endian nation tag, then dispatches
// the province formation-entry action on the global map state.
// FUNCTION: IMPERIALISM 0x00582f20
void TSimMgr::ScSetProvince(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int cityToken;
  cityToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(cityToken);

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_SHORT_TOKEN(nationToken);

  g_pGlobalMapState->ChangeProvinceOwner(static_cast<short>(cityToken),
                                         static_cast<short>(nationToken));
}

// Reads a map-action-context id and a fixed 64-byte inline name, then updates the
// matching context's display name.
// FUNCTION: IMPERIALISM 0x00582fa0
void TSimMgr::ScSetSeazoneName(STurnInstructionCursor* instruction) {

  unsigned int contextToken;
  contextToken = *instruction->tokenCursor;
  const char* rawName =
      reinterpret_cast<const char*>(instruction->tokenCursor) + sizeof(unsigned int);
  instruction->tokenCursor = instruction->tokenCursor + 1;
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
  instruction->tokenCursor = instruction->tokenCursor + 1;
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

// Reads three big-endian 16-bit tokens (source nation, target nation, then relation
// score) and applies them via the diplomacy manager's standing-score setter.
// FUNCTION: IMPERIALISM 0x005831d0
void TSimMgr::ScSetRelationship(STurnInstructionCursor* instruction) {

  unsigned int sourceToken;
  sourceToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(sourceToken);

  unsigned int targetToken;
  targetToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(targetToken);

  unsigned int scoreToken;
  scoreToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(scoreToken);

  g_pDiplomacyTurnStateManager->SetRelationship(sourceToken, targetToken, scoreToken);
}

// Reads a big-endian 32-bit tile-index token followed by a fixed 64-byte inline C-string
// (the province name) and applies it via the global map state's shared-label setter.
// FUNCTION: IMPERIALISM 0x00583270
void TSimMgr::ScSetProvinceName(STurnInstructionCursor* instruction) {

  unsigned int tileToken;
  tileToken = *instruction->tokenCursor;
  const char* rawName =
      reinterpret_cast<const char*>(instruction->tokenCursor) + sizeof(unsigned int);
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(tileToken);

  CString rawText(rawName);
  instruction->tokenCursor += 0x10;
  CString name(rawText);
  g_pGlobalMapState->SetGlobalMapCellSharedLabel(static_cast<int>(tileToken), &name);
}

// Reads two big-endian 32-bit tokens (nation slot, then cash amount) and writes the amount
// into that nation's treasury field.
// FUNCTION: IMPERIALISM 0x00583360
void TSimMgr::ScSetTreasury(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int nationToken;
  nationToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);

  unsigned int cashToken;
  cashToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(cashToken);

  g_apNationStates[static_cast<int>(nationToken)]->treasuryValue10 = static_cast<int>(cashToken);
}

// Reads one big-endian short token (a nation flag/language index), stores it into the
// selected-index field, and refreshes the picture-word-data language pack + strategic map
// bitmap cache (the inlined body of SetSelectedIndex6AAndTriggerRefresh).
// FUNCTION: IMPERIALISM 0x00583400
void TSimMgr::ScSetFlags(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token;
  token = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_SHORT_TOKEN(token);
  short index = static_cast<short>(token);
  field6a = index;
  g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(index);
  g_pMacViewMgr->ReloadBitmap244AndRefreshUiCaches();
}

// Reads two big-endian 32-bit tokens (priority-slot index, then value) and applies the
// value (offset by 1) via the city-order capability state's tier setter.
// FUNCTION: IMPERIALISM 0x00583470
void TSimMgr::ScSetTechDate(STurnInstructionCursor* instruction) {

  unsigned int indexToken;
  indexToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(indexToken);

  unsigned int valueToken;
  valueToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(valueToken);

  g_pTechMgr->SetCityOrderCapabilityTierScaledValueByIndex(static_cast<int>(indexToken),
                                                           static_cast<int>(valueToken + 1));
}

// Reads a big-endian 32-bit owner-nation index and two more big-endian 32-bit tokens (a
// relation-bar type selector, then a value). If the nation's current need for that type is
// below the value, kicks off a resource-yield rebuild; type 0/0x14 first remaps to a fixed
// need slot (1 or 0x13) and tops that need up to its current value before the value used
// below is replaced by the (now-capped) current reading; finally applies the value (needIndex
// = the type selector, or the capped current reading for the 0/0x14 case) via the need
// target/over-cap accumulator.
// FUNCTION: IMPERIALISM 0x00583510
void TSimMgr::ScSetTransportBar(STurnInstructionCursor* instruction) {

  unsigned int ownerToken;
  ownerToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(ownerToken);

  unsigned int typeToken;
  typeToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(typeToken);

  unsigned int valueToken;
  valueToken = *instruction->tokenCursor;
  instruction->tokenCursor = instruction->tokenCursor + 1;
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

// Reads a big-endian 32-bit nation slot, then rebuilds that nation's resource-yield /
// development targets and clears all 0x17 need targets back to zero.
// FUNCTION: IMPERIALISM 0x00583670
void TSimMgr::ScClearTransport(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;
  unsigned int nationToken;
  nationToken = *cursor;
  instruction->tokenCursor = cursor + 1;
  DECODE_SCENARIO_DWORD_TOKEN(nationToken);
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
// state's low byte into councilByDecade, and when the state is
// exactly 2 latches finalCouncilYear to slot*10 + 0x717.
// FUNCTION: IMPERIALISM 0x00583700
void TSimMgr::ScSetCouncilMeeting(STurnInstructionCursor* instruction) {
  unsigned int* cursor = instruction->tokenCursor;

  unsigned int slotToken;
  slotToken = *cursor;
  cursor = cursor + 1;
  instruction->tokenCursor = cursor;
  DECODE_SCENARIO_DWORD_TOKEN(slotToken);

  unsigned int stateToken;
  stateToken = *cursor;
  cursor = cursor + 1;
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
