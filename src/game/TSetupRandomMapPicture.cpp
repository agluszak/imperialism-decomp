#include "game/TSetupRandomMapPicture.h"

#include "game/TApplication.h"
#include "game/TEditText.h"
#include "game/TLanguageMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TRadioTextCluster.h"
#include "game/TSimMgr.h"
#include "game/TUiEvent.h"
#include "game/global_data_tables.h"
// SYNTHETIC: IMPERIALISM 0x00576ca0
// TSetupRandomMapPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576d60
// TSetupRandomMapPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSetupRandomMapPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00576d80
TSetupRandomMapPicture::TSetupRandomMapPicture()
    : TNoHilitePicture(), countryName94(), generatedName(0), initializedA4(0) {}

// SYNTHETIC: IMPERIALISM 0x00576e00
// TSetupRandomMapPicture::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00576e30
// TSetupRandomMapPicture::~TSetupRandomMapPicture
TSetupRandomMapPicture::~TSetupRandomMapPicture() {}

// FUNCTION: IMPERIALISM 0x00577030
void TSetupRandomMapPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005779c0
void TSetupRandomMapPicture::HandleEvent(int commandId, TEventHandler* sourceHandler,
                                         TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00577e40
void TSetupRandomMapPicture::ApplyNationSelectionAndMaybePostTurnEvent5E4() {
  TEditText* countryControl = static_cast<TEditText*>(ResolveControlByTag(0x636f756e /* 'coun' */));
  countryControl->AssertValid();

  CString countryText;
  countryControl->GetCurrentText(&countryText);
  if (g_pSimMgr->useLocalizedNameTables68 != 0) {
    CString localizedName;
    unsigned char duplicateName = 0;
    for (int nationSlot = 0; nationSlot < 0x17 && duplicateName == 0; ++nationSlot) {
      if (nationSlot != selectedNationSlot9A) {
        g_pSimMgr->GetString(0x2715, static_cast<short>(nationSlot), &localizedName);
        duplicateName =
            CompareAnsiStringsWithMbcsAwareness(
                reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(localizedName)),
                reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(countryText))) == 0;
      }
    }
    if (duplicateName != 0) {
      g_pSimMgr->GetString(0x2715, selectedNationSlot9A, &countryText);
    }
  }

  // The unrecovered 0x508910 modal chooses this prefix when the language table
  // exposes country-form variants. Its simple fallback returns delimiter.
  g_cstrCountryNameSettingValue006A4220 = g_szEmptyString;
  g_cstrCountryNameSettingValue006A4220 += g_pLanguageMgr->delimiter;
  g_cstrCountryNameSettingValue006A4220 += countryText;

  TRadioTextCluster* difficultyCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(0x64696666 /* 'diff' */));
  difficultyCluster->AssertValid();
  TControl* selectedDifficulty =
      static_cast<TControl*>(ResolveControlByTag(difficultyCluster->selectedTag88));
  selectedDifficulty->AssertValid();
  int difficulty = selectedDifficulty->controlValue3c;
  g_pSimMgr->SetStateCodeAndUpdateZeroOrOutOfRangeFlag(difficulty);
  g_pSimMgr->preferenceValues[11] = static_cast<short>(difficulty);

  TRadioTextCluster* nameCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(0x6e616d65 /* 'name' */));
  nameCluster->AssertValid();
  g_pSimMgr->useLocalizedNameTables68 = nameCluster->selectedTag88 != 0x72616e64 /* 'rand' */;
  g_pSimMgr->preferenceValues[13] = static_cast<short>(g_pSimMgr->useLocalizedNameTables68);
  g_pSimMgr->InitializeOrLoadEntryArray14AndClampLimits(true);

  g_nRandomMapSelectedNationSlot00698AB0 = selectedNationSlot9A;
  if (g_pSimMgr->field44 != 0) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e4);
    g_pGameFlowState->playerNameMirror = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->playerNameString = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->activeNationTagIndex = static_cast<unsigned char>(selectedNationSlot9A);
    return;
  }

  g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(selectedNationSlot9A);
  SaveSettingValueFromPointerByKey(&g_cstrCountryNameSettingValue006A4220,
                                   g_szCountryNameProfileKey00698AE0);
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    g_pSimMgr->scenarioSetupRows0[nationSlot] = 2;
  }
  g_pSimMgr->scenarioSetupRows0[selectedNationSlot9A] = 1;
  g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
}

// FUNCTION: IMPERIALISM 0x005781f0
void TSetupRandomMapPicture::PostTurnEvent5DCOrResetLocalUiState() {
  unsigned char multiplayerSessionActive = g_pSimMgr->field44 != 0;
  if (multiplayerSessionActive != 0) {
    g_pGameFlowState->ResetLocalUiStateAndPostTurnEvent5E5();
    return;
  }
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
}

// FUNCTION: IMPERIALISM 0x005782f0
void TSetupRandomMapPicture::ForwardParam(int param) {
  TKeyCommandEvent* commandEvent = reinterpret_cast<TKeyCommandEvent*>(param);
  int commandCode = commandEvent->commandCode;
  if (commandCode == 3 || commandCode == 0xd) {
    ApplyNationSelectionAndMaybePostTurnEvent5E4();
  } else if (commandCode == 0x1b) {
    PostTurnEvent5DCOrResetLocalUiState();
  }
}
