#include "game/diplomacy_ui/TInfoPanelView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

#include "game/ui_core/TControl.h"
#include "game/ui_core/TCluster.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004304a0
TInfoPanelView::TInfoPanelView() {
  diplomacyMapView60 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004304d0
// TInfoPanelView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00430500
TInfoPanelView::~TInfoPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f9f60
// TInfoPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f9ff0
// TInfoPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004fa010
void TInfoPanelView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  diplomacyMapView60 = static_cast<TDiplomacyMapView*>(ownerContext);

  // Resource tag array for the four "ovr*" nation labels (ovr0/ovr4/ovr1/ovr2)
  // as laid out by the original instruction sequence.
  const short kOvrTagOffsets[4] = {0, 4, 1, 2};
  for (int i = 0; i < 4; i++) {
    TView* child = ResolveControlByTag(kControlTagOvr0 + kOvrTagOffsets[i]);
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
  COLORREF shadowColor = 0;
  COLORREF foregroundColor = 0;
  selectedNation = diplomacyMapView60->frameRegionSelectorAt98;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);
  ResolveUiThemeColor(0x2b6b, &shadowColor);
  ResolveUiThemeColor(0x2b68, &foregroundColor);

  short baseY = static_cast<short>(0x16f - ownerY);
  short baseX = static_cast<short>(0x48 - ownerX);
  g_pSimMgr->GetString(0x2733, 0, &text); // "Information:"
  SetQuickDrawColorAndSyncGlobals(foregroundColor);
  SetQuickDrawTextOriginWithContextOffset(baseX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowColor);
  SetQuickDrawTextOriginWithContextOffset(baseX, baseY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  g_pSimMgr->GetString(0x2733, 1, &text); // "Provinces:"
  short labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[0] - ownerY);
  short labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[0] - ownerX);
  SetQuickDrawColorAndSyncGlobals(foregroundColor);
  SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowColor);
  SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  if (selectedNation < 7) {
    for (int row = 1; row < 3; ++row) {
      g_pSimMgr->GetString(0x2733, static_cast<short>(row + 1), &text);
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[row] - ownerY);
      labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[row] - ownerX);
      SetQuickDrawColorAndSyncGlobals(foregroundColor);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowColor);
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
      SetQuickDrawColorAndSyncGlobals(foregroundColor);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowColor);
      SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);

      g_pSimMgr->GetString(0x2733, 0x62, &text); // "Trading Nation:"
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
      labelX = static_cast<short>(g_infoPanelLabelXByRow_006969b0[2] - ownerX);
      SetQuickDrawColorAndSyncGlobals(foregroundColor);
      SetQuickDrawTextOriginWithContextOffset(labelX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowColor);
      SetQuickDrawTextOriginWithContextOffset(labelX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  }

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);
  TCountry* selectedCountry = g_apTerrainTypeDescriptorTable[selectedNation];
  selectedCountry->LoadNationDisplayNameSharedRefFromField8(&text);
  short valueX = static_cast<short>(0xa7 - ownerX);
  SetQuickDrawColorAndSyncGlobals(foregroundColor);
  SetQuickDrawTextOriginWithContextOffset(valueX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowColor);
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
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(labelX + 1, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowColor);
    SetQuickDrawTextOriginWithContextOffset(labelX, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&text);
  } else if (selectedCountry != 0 && selectedCountry->encodedNationSlot >= 100 &&
             selectedCountry->encodedNationSlot < 200) {
    short ownerNation = selectedCountry->DecodeOwnerNationSlot();
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&ownerName);
    g_pSimMgr->GetString(0x2733, 0x17, &templateText); // "Anarchy"
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(ownerName));
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(0x79, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowColor);
    SetQuickDrawTextOriginWithContextOffset(0x78, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }

  text.Format(g_szDecimalFormat, selectedCountry->ownedRegionList->GetSize());
  labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[0] - ownerY);
  SetQuickDrawColorAndSyncGlobals(foregroundColor);
  SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
  DrawTextWithCachedQuickDrawStyleState(&text);
  SetQuickDrawColorAndSyncGlobals(shadowColor);
  SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
  DrawTextWithCachedQuickDrawStyleState(&text);

  if (selectedNation < 7) {
    int militaryTier = static_cast<TGreatPower*>(selectedCountry)
                           ->ClassifyNationMilitaryPowerBandAgainstGlobalMean();
    g_pSimMgr->GetString(0x2733, static_cast<short>(militaryTier + 0x19), &text);
    labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[1] - ownerY);
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowColor);
    SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }

  if (selectedNation < 7) {
    if (selectedCountry == 0 || selectedCountry->encodedNationSlot < 100 ||
        selectedCountry->encodedNationSlot >= 200) {
      int productionTier = g_apNationStates[selectedNation]->ClassifyNationProductionTierVsPeers();
      g_pSimMgr->GetString(0x2733, static_cast<short>(productionTier + 0x19), &text);
      labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
      SetQuickDrawColorAndSyncGlobals(foregroundColor);
      SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
      DrawTextWithCachedQuickDrawStyleState(&text);
      SetQuickDrawColorAndSyncGlobals(shadowColor);
      SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  } else if (selectedCountry == 0 || selectedCountry->encodedNationSlot < 100 ||
             selectedCountry->encodedNationSlot >= 200) {
    short favoredNation =
        static_cast<short>(g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(selectedNation));
    if (favoredNation == -1) {
      g_pSimMgr->GetString(0x2733, 0x18, &text); // "None"
    } else {
      g_apTerrainTypeDescriptorTable[favoredNation]->FormatOverlayTerrainLabelText(&text);
    }
    labelY = static_cast<short>(g_infoPanelLabelYByRow_006969c0[2] - ownerY);
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(valueX + 1, labelY + 1);
    DrawTextWithCachedQuickDrawStyleState(&text);
    SetQuickDrawColorAndSyncGlobals(shadowColor);
    SetQuickDrawTextOriginWithContextOffset(valueX, labelY);
    DrawTextWithCachedQuickDrawStyleState(&text);
  }
}

// FUNCTION: IMPERIALISM 0x004facc0
void TInfoPanelView::Setup() {
  TCluster* overlayCluster = static_cast<TCluster*>(ResolveControlByTag(kControlTagClus)); // 'clus'
  overlayCluster->AssertValid();
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), overlayCluster);
  overlayCluster->SetSelectedChildTagAndRefresh(kControlTagOvr0); // 'ovr0'

  diplomacyMapView60->actionCodeBC = kDipActionInspectNation;
  selectedOverlayMode6C = 0;

  TControl* mapKey = static_cast<TControl*>(ResolveControlByTag(kControlTagMkey)); // 'mkey'
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
    TControl* mkey = static_cast<TControl*>(ResolveControlByTag(kControlTagMkey));
    mkey->AssertValid();
    mkey->SetDiplomacyNationSelectionFilterAndRefreshRows(selectedOverlayMode);
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004fae00
void TInfoPanelView::SetInfoCountry(short countryId) {
  memset(countryInfoCategoryIndices64, 0xff, sizeof(countryInfoCategoryIndices64));

  if (countryId < 7) {
    short categoryIndex = 13;
    short categoryCount = 0;
    do {
      if (g_pNationInteractionStateManager->categoryRows[categoryIndex].cells18[46 + countryId] !=
          0) {
        countryInfoCategoryIndices64[categoryCount++] = categoryIndex;
      }
      ++categoryIndex;
    } while (categoryIndex <= 16);
    return;
  }

  TMinor* secondary = g_apSecondaryNationStateSlots[countryId];
  short values[7];
  short indices[7];
  short valueIndex = 0;
  do {
    values[valueIndex] = secondary->diplomacySaveExt13c[valueIndex];
    if (valueIndex == 6 &&
        g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] == 0) {
      values[6] = 0;
    }
    indices[valueIndex] = valueIndex;
    ++valueIndex;
  } while (valueIndex < 7);

  short outer = 0;
  do {
    short inner = outer;
    do {
      if (values[inner] > values[outer]) {
        short temp = values[outer];
        values[outer] = values[inner];
        values[inner] = temp;
        short tempIdx = indices[outer];
        indices[outer] = indices[inner];
        indices[inner] = tempIdx;
      }
      ++inner;
    } while (inner < 7);
    ++outer;
  } while (outer < 6);

  short copyIndex = 0;
  do {
    if (values[copyIndex] > 0) {
      countryInfoCategoryIndices64[copyIndex] = indices[copyIndex];
    }
    ++copyIndex;
  } while (copyIndex < 4);
}
