#include "game/TTacticalHolaPicture.h"

#include "game/CString.h"
#include "game/TCountry.h"
#include "game/TDeluxeText.h"
#include "game/TMapPreviewView.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0045d4b0
// TTacticalHolaPicture::`scalar deleting destructor'
TTacticalHolaPicture::~TTacticalHolaPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad6c0
// TTacticalHolaPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad740
// TTacticalHolaPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalHolaPicture, TPicture)

TTacticalHolaPicture::TTacticalHolaPicture() {}

// Battle-intro ('hola', dialog 0xf19) setup: sets the attacker/defender coat-of-arms
// pictures ('acoa'/'dcoa', bitmap nation + 0xea6), builds the "battle at <city> of
// <opponent nation>" label from string group 0x273d (index 0xc when nation A is the
// local side, 0xd otherwise) into the 'info' deluxe text, and rasterizes the 'pmap'
// owner-palette preview map with the battle site recorded on it.
// FUNCTION: IMPERIALISM 0x005ad760
void TTacticalHolaPicture::ConfigureBattleIntroCoatsAndSiteLabels(int nationA, int nationB,
                                                                  int nationAIsLocalSide,
                                                                  int battleSiteIndex) {
  TPicture* attackerCoat = static_cast<TPicture*>(ResolveControlByTag(kControlTagAttackerCoat));
  attackerCoat->AssertValid();
  attackerCoat->SetPictureResourceIdAndRefresh(static_cast<short>(nationA + 0xea6), 1);
  TPicture* defenderCoat = static_cast<TPicture*>(ResolveControlByTag(kControlTagDefenderCoat));
  defenderCoat->AssertValid();
  defenderCoat->SetPictureResourceIdAndRefresh(static_cast<short>(nationB + 0xea6), 1);

  // Construction (EH-state) order: template, label out, nation label, city name.
  CString siteTemplate;
  CString siteLabelText;
  CString opponentNationLabel;
  CString siteCityName;
  if (nationAIsLocalSide != 0) {
    g_pSimMgr->GetString(0x273d, 0xc, &siteTemplate);
    g_apTerrainTypeDescriptorTable[nationB]->FormatOverlayTerrainLabelText(&opponentNationLabel);
  } else {
    g_pSimMgr->GetString(0x273d, 0xd, &siteTemplate);
    g_apTerrainTypeDescriptorTable[nationA]->FormatOverlayTerrainLabelText(&opponentNationLabel);
  }
  g_pGlobalMapState->AssignCityRecordDisplayName(battleSiteIndex, &siteCityName);
  scanBracketExpressions(g_pSimMgr, &siteLabelText, static_cast<const char*>(siteTemplate),
                         static_cast<const char*>(siteCityName),
                         static_cast<const char*>(opponentNationLabel));

  TDeluxeText* infoControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagInfo));
  infoControl->AssertValid();
  infoControl->UpdateTextEntrySharedString(&siteLabelText);
  infoControl->BuildAndApplyTextStyleDescriptor(0, 0xc, 0x2b6a);
  infoControl->RecenterTextVerticallyFromMeasuredHeightAndMaybeInvalidate(1);

  TMapPreviewView* previewMap =
      static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagPreviewMap));
  previewMap->AssertValid();
  previewMap->TakeSatellitePhoto(0);
  previewMap->selectedRegion64 = battleSiteIndex;
  previewMap->RefreshControl();
}
