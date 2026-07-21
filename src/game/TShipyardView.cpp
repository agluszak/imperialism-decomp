#include "game/TShipyardView.h"

#include "game/TAssetMgr.h"
#include "game/TCluster.h"
#include "game/TCity.h"
#include "game/TCityProductionView.h"
#include "game/TControl.h"
#include "game/TDisplayMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004c8200
// TShipyardView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c82a0
// TShipyardView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardView, TBuildingView)

// Ctor at 0x4c82c0 (`: TBuildingView() { productionView98 = 0; }`) is intentionally NOT
// claimed:
// unlike its TBuildingView siblings, our toolchain does not emit a uniquely-pairable
// out-of-line copy for it, so reccmp hard-fails to match the address. Left markerless
// rather than faking the match.
TShipyardView::TShipyardView() {}

// SYNTHETIC: IMPERIALISM 0x004c82f0
// TShipyardView::`scalar deleting destructor'
TShipyardView::~TShipyardView() {}

// FUNCTION: IMPERIALISM 0x004c8340
void TShipyardView::Free() {
  g_pDisplayMgr->RemoveGWorld(iconSurfaceB8);
  TView::Free();
  if (g_nSaveFormatVersion != 0x4d6f696c) { // 'Moil'
    g_pUiViewManager->CloseFilesFor(0x23f7);
  }
}

// Rebuilds the 8-slot ship-build queue UI: caches the strategic-map view system's
// active-view pointer and a bitmap surface for resource id 0x264f, then for each of
// eight 'but0'-'but7' queue-slot buttons clears its cached value and resets the
// button plus its embedded 'plus'/'minu' stepper controls to the disabled/off state.
// FUNCTION: IMPERIALISM 0x004c8390
void TShipyardView::DoStartup() {
  productionView98 = static_cast<TCityProductionView*>(g_pStrategicMapViewSystem->field04);
  unresolvedZeroB4 = 0;
  iconSurfaceB8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f);

  for (int slotIndex = 0; slotIndex < 8; ++slotIndex) {
    TControl* slotButton =
        static_cast<TControl*>(ResolveControlByTag(0x62757430u + slotIndex)); // 'but0'-'but7'
    slotButton->SetEnabled(0, 1);
    slotButton->SetState(0, 1);
    buildQueueSlotValues[slotIndex] = 0;

    TControl* plusButton =
        static_cast<TControl*>(slotButton->ResolveControlByTag(0x706c7573u)); // 'plus'
    plusButton->AssertValid();
    plusButton->SetState(0, 0);

    TControl* minusButton =
        static_cast<TControl*>(slotButton->ResolveControlByTag(0x6d696e75u)); // 'minu'
    minusButton->AssertValid();
    minusButton->SetState(0, 0);
  }

  // 14-byte style buffer: the 10-byte descriptor plus 4 explicitly zeroed tail bytes (the
  // original zeroes them once before the first Build call) -- same idiom as
  // TBattleReportView::DoPostCreate.
  struct {
    TUiTextStyleDescriptor desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(0x7469746cu)); // 'titl'
  title->AssertValid();
  title->SetTextStyleAndMaybeRefresh(&style.desc, 1);
  title->SetTextFromStringResource(0x2736, 0xe, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  for (int i = 0; i < 2; ++i) {
    TStaticText* fixedLabel =
        static_cast<TStaticText*>(ResolveControlByTag(0x66697830u + i)); // 'fix0'/'fix1'
    fixedLabel->AssertValid();
    fixedLabel->SetTextStyleAndMaybeRefresh(&style.desc, 1);
    fixedLabel->SetTextFromStringResource(0x2736, static_cast<short>(i + 0xf), 1);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TControl* shipName = static_cast<TControl*>(ResolveControlByTag(0x736e616du)); // 'snam'
  shipName->AssertValid();
  shipName->SetTextStyleAndMaybeRefresh(&style.desc, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TControl* description = static_cast<TControl*>(ResolveControlByTag(0x64657363u)); // 'desc'
  description->AssertValid();
  description->SetTextStyleAndMaybeRefresh(&style.desc, 1);

  selectedRequirementRow = 0;
  selectedStatsRowA2 = 0;
  SetShip(buildQueueSlotValues[0]);

  // 'sele' is a TCluster (confirmed by cross-referencing turn_event_dialog_factory.cpp,
  // which builds a real TCluster with controlTag 'sele'); byte 0x1c8 matches
  // TCluster::SetSelectedChildTagAndRefresh(int) exactly (1 arg, RET 4).
  TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(0x73656c65u)); // 'sele'
  sele->AssertValid();
  sele->SetSelectedChildTagAndRefresh(0x62757430); // 'but0'
  UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004c8a50
void TShipyardView::UpdateFields() {
  productionView98->UpdateCityProductionDialogCommodityValueControls();
  RECT refreshRect = {0x16, 0xb4, 0x124, 0xf0};
  InvalidateCityDialogRectRegion(&refreshRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c8ac0
void TShipyardView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // The original dispatches on city94's order receiver via a lookup keyed by
  // city94+0xe4+idx*4 -- its only assignment site, RefreshCityViewProductionDetails
  // (0x4cfbd0, 1748 bytes), is itself unported, so the receiver class is unresolved here
  // too -- not yet ported.
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004c8d70
void TShipyardView::SetShip(short shipType) {}

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

        short haveAmount = city94->CityStockByType(spriteId);
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
    short nCommoditySpriteId = buildQueueSlotValues[selectedRequirementRow];
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
void TShipyardView::GetCostString(CString* output, short actionIndex) {}

// FUNCTION: IMPERIALISM 0x004c9a60
void TShipyardView::SetStats(short shipType) {}

// FUNCTION: IMPERIALISM 0x004c9d20
void TShipyardView::SetStats(TView* sourceControl) {
  short row = static_cast<short>(sourceControl->controlTag & 0xf);
  if (row != selectedStatsRowA2 && buildQueueSlotValues[row] != 0) {
    selectedStatsRowA2 = row;
    SetStats(buildQueueSlotValues[row]);
  }
}
