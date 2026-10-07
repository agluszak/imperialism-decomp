#include "game/city_ui/TUniversityView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/assets/TAssetMgr.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TCluster.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/city/TUnitOrder.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TUniversityView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cac60
TUniversityView::TUniversityView() {
  productionView = 0;
}

// FUNCTION: IMPERIALISM 0x004cacc0
TUniversityView::~TUniversityView() {}

// FUNCTION: IMPERIALISM 0x004cace0
void TUniversityView::DoStartup() {
  productionView = g_pMacViewMgr->activeCityProductionView;

  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  short activeNation = g_pSimMgr->GetPlayerCountry();
  for (short category = 0; category < 9; ++category) {
    if (category == 6 || category == 7) {
      continue;
    }

    int available = g_pTechMgr->universityRecruitmentAvailabilityByNation[activeNation]
                        .availableByCategory[category];
    TControl* selection =
        static_cast<TControl*>(FindSubView(kControlTagCiv0 + category)); // 'civ0'+category
    selection->AssertValid();
    selection->Show(available, 1);
    selection->ViewEnable(available, 0);

    TControl* row =
        static_cast<TControl*>(FindSubView(kControlTagClu0 + category)); // 'clu0'+category
    row->AssertValid();
    row->Show(available, 1);
    if (!available) {
      TControl* plus = static_cast<TControl*>(row->FindSubView(kControlTagPlus)); // 'plus'
      plus->AssertValid();
      plus->ViewEnable(0, 0);
      TControl* minus = static_cast<TControl*>(row->FindSubView(kControlTagMinu)); // 'minu'
      minus->AssertValid();
      minus->ViewEnable(0, 0);
    } else {
      TUnitOrder* order = city->buildOrderSlots[9 + category];
      TNumberText* quantity =
          static_cast<TNumberText*>(row->FindSubView(kControlTagNumb)); // 'numb'
      quantity->AssertValid();
      quantity->ViewEnable(0, 0);
      quantity->InstallTextStyle(style.desc, 1);
      quantity->SetControlValue(order->quantity, 1);
    }
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0x18, 0x2b6b);
  TStaticText* title = static_cast<TStaticText*>(FindSubView(kControlTagTitl)); // 'titl'
  title->AssertValid();
  title->InstallTextStyle(style.desc, 1);
  title->SetTextWithStrListID(0x2723, 0xa, true);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TStaticText* unit = static_cast<TStaticText*>(FindSubView(kControlTagUnit)); // 'unit'
  unit->AssertValid();
  unit->InstallTextStyle(style.desc, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  for (short fixedLabelIndex = 0; fixedLabelIndex < 2; ++fixedLabelIndex) {
    TStaticText* label =
        static_cast<TStaticText*>(FindSubView(kControlTagFix0 + fixedLabelIndex)); // 'fix0'/'fix1'
    label->AssertValid();
    label->InstallTextStyle(style.desc, 1);
    label->SetTextWithStrListID(0x2723, static_cast<short>(0xb + fixedLabelIndex), true);
  }

  TStaticText* description = static_cast<TStaticText*>(FindSubView(kControlTagDesc)); // 'desc'
  description->AssertValid();
  description->InstallTextStyle(style.desc, 1);

  for (short requirementLabelIndex = 0; requirementLabelIndex < 3; ++requirementLabelIndex) {
    TStaticText* label = static_cast<TStaticText*>(
        FindSubView(kControlTagFix2 + requirementLabelIndex)); // 'fix2'..'fix4'
    label->AssertValid();
    label->InstallTextStyle(style.desc, 1);
    label->SetTextWithStrListID(0x2723, static_cast<short>(0xe + requirementLabelIndex), true);
    label->Show(0, 1);
    label->SetJustification(1, false);
  }

  static const unsigned int kStyledValueTags[6] = {kControlTagCash, kControlTagTrea,
                                                   kControlTagApap, kControlTagCpap,
                                                   kControlTagAexp, kControlTagCexp};
  for (short valueIndex = 0; valueIndex < 6; ++valueIndex) {
    TControl* value = static_cast<TControl*>(FindSubView(kStyledValueTags[valueIndex]));
    value->AssertValid();
    value->InstallTextStyle(style.desc, 1);
  }

  selectedRecruitmentCategory = -1;
  selectedRecruitmentOrder = 0;
  TCluster* selection = static_cast<TCluster*>(FindSubView(kControlTagSele)); // 'sele'
  selection->AssertValid();
  selection->SetCurrentChoice(kControlTagCiv0); // 'civ0'
  selectedRecruitmentCategory = 0;
  SetUnit(0);
}

// FUNCTION: IMPERIALISM 0x004cb320
void TUniversityView::SetUnit(short recruitmentCategory) {
  CString currencyText;
  CString unusedText;
  TUnitOrder* order = city->buildOrderSlots[9 + recruitmentCategory];
  if (order == selectedRecruitmentOrder) {
    return;
  }
  selectedRecruitmentOrder = order;

  CRect invalidRect;
  TStaticText* unit = static_cast<TStaticText*>(FindSubView(kControlTagUnit)); // 'unit'
  unit->AssertValid();
  unit->SetTextWithStrListID(0x2718, static_cast<short>(recruitmentCategory + 1), false);
  unit->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TNumberText* paperCost = static_cast<TNumberText*>(FindSubView(kControlTagCpap)); // 'cpap'
  paperCost->AssertValid();
  paperCost->SetControlValue(order->primaryInputPerUnit, 0);
  paperCost->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TStaticText* cashCost = static_cast<TStaticText*>(FindSubView(kControlTagCash)); // 'cash'
  cashCost->AssertValid();
  g_pSimMgr->NumToCurrency(order->cashCostPerUnit, &currencyText);
  cashCost->SetTextAndMaybeRefresh(&currencyText, false);
  cashCost->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TStaticText* description = static_cast<TStaticText*>(FindSubView(kControlTagDesc)); // 'desc'
  description->AssertValid();
  description->SetTextWithStrListID(0x2751, recruitmentCategory, false);
  description->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  UpdateFields();
  RECT unitPreviewRect = {0x7c, 0x5c, 0xbc, 0x9c};
  InvalidateCityDialogRectRegion(&unitPreviewRect, 1);
  RECT requirementGridRect = {0, 0x104, 0xc8, 0x186};
  InvalidateCityDialogRectRegion(&requirementGridRect, 1);

  if (selectedRecruitmentCategory > -1) {
    short highestRequirementLevel = 0;
    short activeNation = g_pSimMgr->GetPlayerCountry();
    for (short row = 0; row < 4; ++row) {
      short resourceType = static_cast<short>(
          g_anUniversityRequirementIdByRecruitRow[selectedRecruitmentCategory][row]);
      if (resourceType != -1) {
        short level = g_pTechMgr->capabilityValueByNationAndResource[activeNation][resourceType];
        if (highestRequirementLevel < level) {
          highestRequirementLevel = level;
        }
      }
    }

    short level;
    for (level = 0; level < highestRequirementLevel; ++level) {
      TView* label = FindSubView(kControlTagFix2 + level); // 'fix2'+level
      label->AssertValid();
      label->Show(1, 1);
    }
    for (; level < 3; ++level) {
      TView* label = FindSubView(kControlTagFix2 + level); // 'fix2'+level
      label->AssertValid();
      label->Show(0, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004cb8a0
void TUniversityView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short index =
        static_cast<short>(sourceHandler->controlTag) - 0x7630; // 'rec0'-'rec8' low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentCategory = index;
      SetUnit(index);
    }
  } else if (commandId == 0xa) {
    TView* ownerView = static_cast<TView*>(sourceHandler)->ownerContext;
    short index = static_cast<short>(ownerView->controlTag) - 0x7530; // low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentCategory = index;
      SetUnit(index);

      // 'sele' is a TCluster (see TShipyardView::DoStartup's identical tail).
      TCluster* sele = static_cast<TCluster*>(FindSubView(kControlTagSele)); // 'sele'
      sele->AssertValid();
      sele->SetCurrentChoice(kControlTagCiv0 + index); // 'civ0'+index

      TUnitOrder* order = city->buildOrderSlots[9 + index];
      short quantity = order->quantity;
      if (sourceHandler->controlTag == kControlTagPlus) { // 'plus'
        ++quantity;
      } else {
        --quantity;
      }
      if (order->SetQuantity(quantity)) {
        TView* quantityPanel = FindSubView(kControlTagNum0 + index); // 'num0'+index
        quantityPanel->AssertValid();
        TNumberText* quantityText =
            static_cast<TNumberText*>(quantityPanel->FindSubView(kControlTagNumb)); // 'numb'
        quantityText->AssertValid();
        quantityText->SetControlValue(order->quantity, 0);

        CRect invalidRect;
        quantityText->GetFrame(&invalidRect);
        quantityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);
        UpdateFields();
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cbb20
void TUniversityView::UpdateFields() {
  COLORREF normalTextColor;
  COLORREF warningTextColor;
  ResolveUiThemeColor(0x2b6b, &normalTextColor);
  ResolveUiThemeColor(0x2b69, &warningTextColor);

  if (selectedRecruitmentOrder == 0) {
    return;
  }

  TNumberText* paperAvailable = static_cast<TNumberText*>(FindSubView(kControlTagApap)); // 'apap'
  paperAvailable->AssertValid();
  paperAvailable->SetControlValue(city->stockByType[kResourcePaper], 0);
  paperAvailable->SetTextColorAndMaybeRefresh(city->stockByType[kResourcePaper] <
                                                      selectedRecruitmentOrder->primaryInputPerUnit
                                                  ? &warningTextColor
                                                  : &normalTextColor,
                                              true);
  CRect invalidRect;
  paperAvailable->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TPopulationMgr* population = city->productionSummary;
  short recruitmentCapacity = population->strength / 4;
  if (population->productionSlots->highSkillCount < recruitmentCapacity) {
    recruitmentCapacity = population->productionSlots->highSkillCount;
  }

  TNumberText* capacityAvailable =
      static_cast<TNumberText*>(FindSubView(kControlTagAexp)); // 'aexp'
  capacityAvailable->AssertValid();
  capacityAvailable->SetControlValue(recruitmentCapacity, 0);
  capacityAvailable->SetTextColorAndMaybeRefresh(
      recruitmentCapacity < 1 ? &warningTextColor : &normalTextColor, true);
  capacityAvailable->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  CString treasuryText;
  int treasury = city->ownerNation->treasuryValue;
  g_pSimMgr->NumToCurrency(treasury, &treasuryText);

  TStaticText* treasuryAvailable =
      static_cast<TStaticText*>(FindSubView(kControlTagTrea)); // 'trea'
  treasuryAvailable->AssertValid();
  treasuryAvailable->SetTextAndMaybeRefresh(&treasuryText, false);
  treasuryAvailable->SetTextColorAndMaybeRefresh(
      treasury < selectedRecruitmentOrder->cashCostPerUnit ? &warningTextColor : &normalTextColor,
      true);
  treasuryAvailable->GetFrame(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  productionView->UpdateUnits();
}

// FUNCTION: IMPERIALISM 0x004cbf30
void TUniversityView::Free() {
  TView::Free();
  if (g_nSaveFormatVersion != kControlTagMoil) { // 'Moil'
    g_pAssetMgr->CloseFilesFor(0x23fa);
  }
}

// FUNCTION: IMPERIALISM 0x004cbf70
void TUniversityView::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);

  int nHighestRequirementLevel = 0;
  short baseOffset = g_pGlobalMapState->GetUnitOffset(selectedRecruitmentCategory, false, 1);
  UpdatePaletteIndexWithDefaultFallback(0x10);

  RECT panelRect = {0x7c, 0x5c, 0xbc, 0x9c};
  RECT scratchClip;
  if (SectRect(&panelRect, rectBuffer, &scratchClip)) {
    RECT srcRect = {baseOffset, 0, baseOffset + 0x40, 0x40};
    BlitRectWithOptionalTransparency(g_pMacViewMgr->improvementTileWorld->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &panelRect, 0x24, 0);
  }

  RECT gridRegion = {0, 0xff, 0xc8, 0x186};
  if (SectRect(&gridRegion, rectBuffer, &scratchClip)) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
    int row = 0;
    for (int rowBottomY = 0x12e; rowBottomY < 0x192; rowBottomY += 0x19, ++row) {
      CString text;
      short nCommoditySpriteId = static_cast<short>(
          g_anUniversityRequirementIdByRecruitRow[selectedRecruitmentCategory][row]);
      if (nCommoditySpriteId != -1) {
        RECT reqSrcRect = {nCommoditySpriteId * 0x14, 0, (nCommoditySpriteId + 1) * 0x14, 0x18};
        RECT reqDstRect = {0x19, rowBottomY - 0x1c, 0x2d, rowBottomY};
        BlitRectWithOptionalTransparency(g_pMacViewMgr->unitIconAtlas->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &reqSrcRect, &reqDstRect, 0x24, 0);

        short activeNationId = g_pSimMgr->GetPlayerCountry();
        short capabilityLevel =
            g_pTechMgr->capabilityValueByNationAndResource[activeNationId][nCommoditySpriteId];
        if (nHighestRequirementLevel < capabilityLevel) {
          nHighestRequirementLevel = capabilityLevel;
        }
        for (int level = 1; level <= nHighestRequirementLevel; ++level) {
          text.Format(g_szDecimalFormat,
                      static_cast<int>(static_cast<signed char>(
                          g_abUniversityRequirementLevelById[nCommoditySpriteId][level])));
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(level * 0x28 + 0x27),
                                                  static_cast<short>(row * 0x19 + 0x121));
          DrawTextWithCachedQuickDrawStyleState(&text);
        }
      }
    }
  }

  UpdatePaletteIndexWithDefaultFallback(0x13);
}
