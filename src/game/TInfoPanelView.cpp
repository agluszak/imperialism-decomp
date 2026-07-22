#include "game/TInfoPanelView.h"

#include "game/TControl.h"
#include "game/TCluster.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDiplomacyMapView.h"
#include "game/TGreatPower.h"
#include "game/TMinor.h"
#include "game/TSimMgr.h"
#include "game/TTradeMgr.h"
#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004304d0
// TInfoPanelView::`scalar deleting destructor'
TInfoPanelView::~TInfoPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f9f60
// TInfoPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f9ff0
// TInfoPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoPanelView, TPanelView)

TInfoPanelView::TInfoPanelView() {}

// FUNCTION: IMPERIALISM 0x004fa010
void TInfoPanelView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  diplomacyMapView60 = static_cast<TDiplomacyMapView*>(ownerContext);

  // Resource tag array for the four "ovr*" nation labels (ovr0/ovr4/ovr1/ovr2)
  // as laid out by the original instruction sequence.
  const short kOvrTagOffsets[4] = {0, 4, 1, 2};
  for (int i = 0; i < 4; i++) {
    TView* child = ResolveControlByTag(0x6f767230 + kOvrTagOffsets[i]);
    child->AssertValid();
    CString text;
    g_pSimMgr->GetString(0x2733, (short)(0x4e + i), &text);
    SetControlHoverHelpText(text, child);
  }

  CString empty(g_szEmptyString);
  SetControlHoverHelpText(empty, this);
}

// FUNCTION: IMPERIALISM 0x004fa190
void TInfoPanelView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  CString text;
  CString unusedText;
  short selectedNation;
  CString ownerName;
  CString templateText;

  short ownerY = static_cast<short>(ownerLocalY);
  short ownerX = static_cast<short>(ownerLocalX);
  int shadowStyle = 0;
  int foregroundStyle = 0;
  selectedNation = diplomacyMapView60->frameRegionSelectorAt98;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);
  MapUiThemeCodeToStyleFlags(0x2b6b, &shadowStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &foregroundStyle);

  short baseY = static_cast<short>(0x16f - ownerY);
  short baseX = static_cast<short>(0x48 - ownerX);
  g_pSimMgr->GetString(0x2733, 0, &text); // "Information:"
  SetQuickDrawColorAndSyncGlobals(foregroundStyle);
  SetQuickDrawTextOriginWithContextOffset(baseX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(baseX, baseY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  g_pSimMgr->GetString(0x2733, 1, &text); // "Provinces:"
  short labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[0] - ownerY);
  short labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[0] - ownerX);
  SetQuickDrawColorAndSyncGlobals(foregroundStyle);
  SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  if (selectedNation < 7) {
    for (int row = 1; row < 3; ++row) {
      g_pSimMgr->GetString(0x2733, static_cast<short>(row + 1), &text);
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[row] - ownerY);
      labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[row] - ownerX);
      SetQuickDrawColorAndSyncGlobals(foregroundStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  } else {
    TCountry* selectedCountry = g_apTerrainTypeDescriptorTable[selectedNation];
    if (selectedCountry == 0 || selectedCountry->encodedNationSlot < 100 ||
        selectedCountry->encodedNationSlot >= 200) {
      g_pSimMgr->GetString(0x2733, 0x61, &text); // "Most Favored"
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[1] - ownerY);
      labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[1] - ownerX);
      SetQuickDrawColorAndSyncGlobals(foregroundStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);

      g_pSimMgr->GetString(0x2733, 0x62, &text); // "Trading Nation:"
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
      labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[2] - ownerX);
      SetQuickDrawColorAndSyncGlobals(foregroundStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowStyle);
      SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  }

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);
  TCountry* selectedCountry = g_apTerrainTypeDescriptorTable[selectedNation];
  selectedCountry->LoadNationDisplayNameSharedRefFromField8(&text);
  short valueX = static_cast<short>(0xa7 - ownerX);
  SetQuickDrawColorAndSyncGlobals(foregroundStyle);
  SetQuickDrawTextOriginWithContextOffset(valueX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(valueX, baseY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  if (selectedCountry->encodedNationSlot >= 200) {
    short ownerNation = selectedCountry->DecodeOwnerNationSlot();
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&ownerName);
    g_pSimMgr->GetString(0x2733, 0x16, &templateText); // "Colony of [1:Zimm]"
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(ownerName));
    labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[1] - ownerX);
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(labelX + 1, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(labelX, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&text);
  } else if (selectedCountry != 0 && selectedCountry->encodedNationSlot >= 100 &&
             selectedCountry->encodedNationSlot < 200) {
    short ownerNation = selectedCountry->DecodeOwnerNationSlot();
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&ownerName);
    g_pSimMgr->GetString(0x2733, 0x17, &templateText); // "Anarchy"
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(ownerName));
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(0x79, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(0x78, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }

  text.Format(g_szDecimalFormat, selectedCountry->ownedRegionList->GetSize());
  labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[0] - ownerY);
  SetQuickDrawColorAndSyncGlobals(foregroundStyle);
  SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  if (selectedNation < 7) {
    int militaryTier = static_cast<TGreatPower*>(selectedCountry)
                           ->ClassifyNationMilitaryPowerBandAgainstGlobalMean();
    g_pSimMgr->GetString(0x2733, static_cast<short>(militaryTier + 0x19), &text);
    labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[1] - ownerY);
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }

  if (selectedNation < 7) {
    if (selectedCountry == 0 || selectedCountry->encodedNationSlot < 100 ||
        selectedCountry->encodedNationSlot >= 200) {
      int productionTier = g_apNationStates[selectedNation]->ClassifyNationProductionTierVsPeers();
      g_pSimMgr->GetString(0x2733, static_cast<short>(productionTier + 0x19), &text);
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
      SetQuickDrawColorAndSyncGlobals(foregroundStyle);
      SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowStyle);
      SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  } else if (selectedCountry == 0 || selectedCountry->encodedNationSlot < 100 ||
             selectedCountry->encodedNationSlot >= 200) {
    short favoredNation = static_cast<short>(
        g_pDiplomacyTurnStateManager->SelectBestMajorNationForMinorByStandingAndNeed(
            selectedNation));
    if (favoredNation == -1) {
      g_pSimMgr->GetString(0x2733, 0x18, &text); // "None"
    } else {
      g_apTerrainTypeDescriptorTable[favoredNation]->FormatOverlayTerrainLabelText(&text);
    }
    labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }
}

// FUNCTION: IMPERIALISM 0x004facc0
void TInfoPanelView::Setup() {
  TCluster* overlayCluster = static_cast<TCluster*>(ResolveControlByTag(0x636c7573)); // 'clus'
  overlayCluster->AssertValid();
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), overlayCluster);
  overlayCluster->SetSelectedChildTagAndRefresh(0x6f767230); // 'ovr0'

  diplomacyMapView60->actionCodeBC = kDipActionInspectNation;
  selectedOverlayMode6C = 0;

  TControl* mapKey = static_cast<TControl*>(ResolveControlByTag(0x6d6b6579)); // 'mkey'
  mapKey->AssertValid();
  mapKey->SetDiplomacyNationSelectionFilterAndRefreshRows(0);
}

// FUNCTION: IMPERIALISM 0x004fad60
void TInfoPanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short selectedOverlayMode = (short)sourceHandler->controlTag - 0x7230;
    diplomacyMapView60->interactionModeAt94 = selectedOverlayMode;
    InvalidateCityDialogRectRegion(&diplomacyMapView60->mapViewportRect514, 1);
    selectedOverlayMode6C = selectedOverlayMode;
    TControl* mkey = static_cast<TControl*>(ResolveControlByTag(0x6d6b6579));
    mkey->AssertValid();
    mkey->SetDiplomacyNationSelectionFilterAndRefreshRows(selectedOverlayMode);
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004fae00
void TInfoPanelView::SetInfoCountry(short countryId) {
  // Initialize the 8-byte/4-short field array to -1.
  *(reinterpret_cast<int*>(&countryInfoCategoryIndices64[0])) = -1;
  *(reinterpret_cast<int*>(&countryInfoCategoryIndices64[2])) = -1;

  if (countryId < 7) {
    // Great-power row: scan 0x898 + 2*countryId + i*0xa0 for i=0..3 and store
    // the first four non-zero values as 13, 14, 15, 16.
    short* base = reinterpret_cast<short*>(
        reinterpret_cast<char*>(g_pNationInteractionStateManager) + 0x898 + countryId * 2);
    int count = 0;
    for (int i = 0; i < 4; i++) {
      if (base[i * 80] != 0) {
        countryInfoCategoryIndices64[count++] = (short)(13 + i);
      }
    }
  } else {
    // Minor-power row: bubble-sort the first 7 values from
    // secondary->diplomacySaveExt13c[0..6], then copy the first 4 positive
    // indices into countryInfoCategoryIndices64.
    TMinor* secondary = g_apSecondaryNationStateSlots[countryId];
    short values[7];
    short indices[7];
    for (int idx = 0; idx < 7; idx++) {
      values[idx] = secondary->diplomacySaveExt13c[idx];
      if (idx == 6 &&
          g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] ==
              0) {
        values[6] = 0;
      }
      indices[idx] = (short)idx;
    }

    // Selection sort descending by values.
    for (int outer = 0; outer < 6; outer++) {
      for (int inner = outer; inner < 7; inner++) {
        if (values[inner] > values[outer]) {
          short temp = values[outer];
          values[outer] = values[inner];
          values[inner] = temp;
          short tempIdx = indices[outer];
          indices[outer] = indices[inner];
          indices[inner] = tempIdx;
        }
      }
    }

    for (int copyIdx = 0; copyIdx < 4; copyIdx++) {
      if (values[copyIdx] > 0) {
        countryInfoCategoryIndices64[copyIdx] = indices[copyIdx];
      }
    }
  }
}
