#include "game/TShipyardView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x004c8200
// TShipyardView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c82a0
// TShipyardView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardView, TBuildingView)

// Ctor at 0x4c82c0 (`: TBuildingView() { field98 = 0; }`) is intentionally NOT claimed:
// unlike its TBuildingView siblings, our toolchain does not emit a uniquely-pairable
// out-of-line copy for it, so reccmp hard-fails to match the address. Left markerless
// rather than faking the match.
TShipyardView::TShipyardView() {}

// SYNTHETIC: IMPERIALISM 0x004c82f0
// TShipyardView::`scalar deleting destructor'
TShipyardView::~TShipyardView() {}

// FUNCTION: IMPERIALISM 0x004c8340
void TShipyardView::Free() {}

// FUNCTION: IMPERIALISM 0x004c8390
undefined TShipyardView::OrphanRetStub_004c6fd0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c8a50
undefined TShipyardView::OrphanRetStub_004c6fb0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c8ac0
void TShipyardView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x004c8d70
void TShipyardView::InitializeCityViewActionButtons() {}

// Draws two dialog sections, each gated by whether it intersects the passed-in
// paint rect (SectRect): (1) the "commodities in production" icon strip -- up to 4
// commoditySpriteIds slots, each blitting the resource icon twice (rows at y=0x98 and
// y=0xcc) plus the required amount and the current stock (colored red when short); and
// (2) the selected resource's 6-column requirement metrics grid, each column a
// GetString(0x2736) header over a resource-descriptor-derived value. Position/lookup
// tables below are transcribed verbatim from the original's immediate-value stack
// stores; their last few entries land in gaps the original never explicitly
// initializes (an apparent original-binary quirk), ported as 0 rather than guessed.
// FUNCTION: IMPERIALISM 0x004c9150
void TShipyardView::ApplyRectSlot110(RECT* rectBuffer) {
  CString text;
  TPicture::ApplyRectSlot110(rectBuffer);
  UpdatePaletteIndexWithDefaultFallback(0x10);

  RECT commodityStripRegion = {0x16, 0x82, 0xe5, 0xc4};
  RECT scratchClip;
  if (SectRect(&commodityStripRegion, rectBuffer, &scratchClip)) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
    int x = 0x3a;
    for (int slot = 0; slot < 4; ++slot) {
      short spriteId = commoditySpriteIds[slot];
      if (spriteId != -1) {
        RECT srcRect = {spriteId * 0x20, 0, (spriteId + 1) * 0x20, 0x18};
        RECT dstRectTop = {x - 0x20, 0x98, x, 0xb0};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &srcRect, &dstRectTop, 0x24, 0);
        RECT dstRectBottom = {x - 0x20, 0xcc, x, 0xe4};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &srcRect, &dstRectBottom, 0x24, 0);

        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(x), 0xb2);
        text.Format(g_szDecimalFormat, static_cast<int>(commodityRequiredAmounts[slot]));
        DrawTextWithCachedQuickDrawStyleState(&text);

        short haveAmount = field94[0x5b + spriteId];
        text.Format(g_szDecimalFormat, static_cast<int>(haveAmount));
        if (haveAmount < commodityRequiredAmounts[slot]) {
          ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b69);
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(x), 0xe6);
          DrawTextWithCachedQuickDrawStyleState(&text);
          ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
        } else {
          ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(x), 0xe6);
          DrawTextWithCachedQuickDrawStyleState(&text);
        }
      }
      x += 0x28;
    }
  }

  RECT requirementGridRegion = {0x19, 0x4b, 0xc4, 0x80};
  if (SectRect(&requirementGridRegion, rectBuffer, &scratchClip)) {
    short nCommoditySpriteId = requirementResourceTypeByRow[selectedRequirementRow];
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);

    // Column header Y/X positions (6 columns); the last X entry is never explicitly
    // stored in the original (reads adjacent stack data there) -- ported as 0.
    static const short kColumnHeaderY[6] = {0x2d, 0x46, 0x32, 0x1e, 0x19, 0x23};
    static const short kColumnHeaderX[6] = {0x41, 0x23, 0x28, 0x19, 0, 0};
    // Case-3 per-resource-type metric table (resource types 0-10), transcribed
    // verbatim; semantics not otherwise recovered.
    static const short kCaseThreeMetricByResourceType[11] = {0x78, 0x78, 0x1c, 0x1c, 0x1c, 0x76,
                                                             0x66, 0x56, 0x76, 0x66, 0x56};

    for (int column = 0; column < 6; ++column) {
      g_pSimMgr->GetString(0x2736, static_cast<short>(column + 0x10), &text);
      short headerY = kColumnHeaderY[column];
      short headerX = kColumnHeaderX[column];
      SetQuickDrawTextOriginWithContextOffset(headerX, headerY);
      DrawTextWithCachedQuickDrawStyleState(&text);

      int metricValue = 0;
      bool haveMetric = true;
      switch (column) {
      case 0:
        metricValue = GetResourceTypeRandomDrawBlockFlag(nCommoditySpriteId) / 100;
        break;
      case 1:
        metricValue = GetResourceDescriptorWord0CByType(nCommoditySpriteId);
        break;
      case 2:
        metricValue = 100 - GetResourceDescriptorWord10ByType(nCommoditySpriteId);
        break;
      case 3:
        metricValue = kCaseThreeMetricByResourceType[nCommoditySpriteId];
        break;
      case 4:
        metricValue = GetResourceDescriptorWord18ByType(nCommoditySpriteId);
        break;
      case 5:
        metricValue = GetResourceDescriptorWeightWord0ByType(nCommoditySpriteId);
        break;
      default:
        haveMetric = false;
        break;
      }
      if (haveMetric) {
        text.Format(g_szDecimalFormat, metricValue);
      }
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(headerX + 0x3c), headerY);
      DrawTextWithCachedQuickDrawStyleState(&text);
    }
  }

  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x004c97c0
undefined TShipyardView::BuildIndustryActionCostSummaryTextByActionIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c9a60
void __fastcall TShipyardView::RefreshCityViewStatusPanel(int* pCityViewDialog) {}

// FUNCTION: IMPERIALISM 0x004c9d20
undefined TShipyardView::OrphanCallChain_C1_I15_004c9d20(int param_1) {
  return 0;
}
