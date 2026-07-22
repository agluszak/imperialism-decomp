#include "game/TUniversityView.h"

#include "game/TAssetMgr.h"
#include "game/TCity.h"
#include "game/TCityProductionView.h"
#include "game/TCluster.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TNumberText.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTechMgr.h"
#include "game/TUnitOrder.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004caba0
// TUniversityView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cac40
// TUniversityView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUniversityView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cac60
TUniversityView::TUniversityView() {}

// SYNTHETIC: IMPERIALISM 0x004cac90
// TUniversityView::`scalar deleting destructor'
TUniversityView::~TUniversityView() {}

// FUNCTION: IMPERIALISM 0x004cace0
void TUniversityView::DoStartup() {}

// FUNCTION: IMPERIALISM 0x004cb320
void TUniversityView::SetUnit(short recruitmentCategory) {}

// FUNCTION: IMPERIALISM 0x004cb8a0
void TUniversityView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short index =
        static_cast<short>(sourceHandler->controlTag) - 0x7630; // 'rec0'-'rec8' low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentCategoryA4 = index;
      SetUnit(index);
    }
  } else if (commandId == 0xa) {
    TView* ownerView = static_cast<TView*>(sourceHandler)->ownerContext;
    short index = static_cast<short>(ownerView->controlTag) - 0x7530; // low 16 bits
    if (index >= 0 && index < 9) {
      selectedRecruitmentCategoryA4 = index;
      SetUnit(index);

      // 'sele' is a TCluster (see TShipyardView::DoStartup's identical tail).
      TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(0x73656c65u)); // 'sele'
      sele->AssertValid();
      sele->SetSelectedChildTagAndRefresh(0x63697630 + index); // 'civ0'+index

      // The original then dispatches to the real receiver at city94[index+0x22] (city94's
      // pointee class is unresolved -- see RefreshCityViewProductionDetails, 0x4cfbd0, 1748
      // bytes) which drives a 'num0'+index control's embedded 'numb' widget and a final
      // invalidate/refresh sequence -- not yet ported.
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cbb20
void TUniversityView::UpdateFields() {
  int normalTextColor;
  int warningTextColor;
  MapUiThemeCodeToStyleFlags(0x2b6b, &normalTextColor);
  MapUiThemeCodeToStyleFlags(0x2b69, &warningTextColor);

  if (selectedRecruitmentOrderA8 == 0) {
    return;
  }

  TNumberText* paperAvailable =
      static_cast<TNumberText*>(ResolveControlByTag(0x61706170u)); // 'apap'
  paperAvailable->AssertValid();
  paperAvailable->SetControlValue(city94->cityStockPaperCA, 0);
  paperAvailable->SetTextColorAndMaybeRefresh(
      city94->cityStockPaperCA < selectedRecruitmentOrderA8->primaryInputPerUnit ? &warningTextColor
                                                                                 : &normalTextColor,
      true);
  CRect invalidRect;
  paperAvailable->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TPopulationMgr* population = city94->productionSummary1d8;
  short recruitmentCapacity = static_cast<short>(population->strength / 4);
  if (population->productionSlots14->highSkillCount08 < recruitmentCapacity) {
    recruitmentCapacity = population->productionSlots14->highSkillCount08;
  }

  TNumberText* capacityAvailable =
      static_cast<TNumberText*>(ResolveControlByTag(0x61657870u)); // 'aexp'
  capacityAvailable->AssertValid();
  capacityAvailable->SetControlValue(recruitmentCapacity, 0);
  capacityAvailable->SetTextColorAndMaybeRefresh(
      recruitmentCapacity < 1 ? &warningTextColor : &normalTextColor, true);
  capacityAvailable->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  CString treasuryText;
  int treasury = city94->ownerNationAc->treasuryValue10;
  g_pSimMgr->NumToCurrency(treasury, &treasuryText);

  TStaticText* treasuryAvailable =
      static_cast<TStaticText*>(ResolveControlByTag(0x74726561u)); // 'trea'
  treasuryAvailable->AssertValid();
  treasuryAvailable->SetTextAndMaybeRefresh(&treasuryText, 0);
  treasuryAvailable->SetTextColorAndMaybeRefresh(
      treasury < selectedRecruitmentOrderA8->cashCostPerUnit ? &warningTextColor : &normalTextColor,
      true);
  treasuryAvailable->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  productionView98->UpdateUnits();
}

// FUNCTION: IMPERIALISM 0x004cbf30
void TUniversityView::Free() {
  TView::Free();
  if (g_nSaveFormatVersion != 0x4d6f696c) { // 'Moil'
    g_pUiViewManager->CloseFilesFor(0x23fa);
  }
}

// Two dialog sections, each SectRect-gated against the passed-in paint rect: (1) a
// fixed 0x40x0x40 preview-panel blit whose source frame is selected by
// GetMapImprovementSpriteBaseOffset(selectedRecruitmentCategoryA4); (2) the selected recruitment category's
// requirement grid, one row per resource
// (g_UniversityRequirementResourceTypeTable[row + selectedRecruitmentCategoryA4*4], -1 = empty), each row
// blitting the resource icon and drawing up to nHighestRequirementLevel columns of its
// per-nation capability level. Exact on-screen rect positions for the panel/per-row
// icon blits are approximate (the original reuses a stack scratch rect across several
// calls in a way that could not be fully untangled) but every call and its arguments
// are faithfully reproduced.
// FUNCTION: IMPERIALISM 0x004cbf70
void TUniversityView::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);

  int nHighestRequirementLevel = 0;
  short baseOffset =
      g_pGlobalMapState->GetMapImprovementSpriteBaseOffset(selectedRecruitmentCategoryA4, 0, 1);
  UpdatePaletteIndexWithDefaultFallback(0x10);

  RECT panelRect = {0, 0, 0x40, 0x40};
  RECT scratchClip;
  if (SectRect(&panelRect, rectBuffer, &scratchClip)) {
    RECT srcRect = {baseOffset, 0, baseOffset + 0x40, 0x40};
    BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas66c->GetBlitSurface(),
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
          g_UniversityRequirementResourceTypeTable[row + selectedRecruitmentCategoryA4 * 4]);
      if (nCommoditySpriteId != -1) {
        RECT reqSrcRect = {nCommoditySpriteId * 0x14, 0, (nCommoditySpriteId + 1) * 0x14, 0x18};
        RECT reqDstRect = {2, rowBottomY - 0x19, 2 + 0x14, rowBottomY - 1};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->unitIconAtlas->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &reqSrcRect, &reqDstRect, 0x24, 0);

        short activeNationId = g_pSimMgr->GetActiveNationId();
        short capabilityLevel =
            g_pCityOrderCapabilityState
                ->capabilityValueByNationAndResource[activeNationId][nCommoditySpriteId];
        if (nHighestRequirementLevel < capabilityLevel) {
          nHighestRequirementLevel = capabilityLevel;
        }
        for (int level = 1; level <= nHighestRequirementLevel; ++level) {
          text.Format(
              g_szDecimalFormat,
              static_cast<int>(g_abUniversityRequirementLevelById[nCommoditySpriteId][level]));
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(level * 0x28 + 0x27),
                                                  static_cast<short>(row * 0x19 + 0x121));
          DrawTextWithCachedQuickDrawStyleState(&text);
        }
      }
    }
  }

  UpdatePaletteIndexWithDefaultFallback(0x13);
}
