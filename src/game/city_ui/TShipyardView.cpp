#include "game/city_ui/TShipyardView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TCluster.h"
#include "game/app/TOverlayRadioButton.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/city/TShipOrder.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/global_types.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/navy_order.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004c8200
// TShipyardView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c82a0
// TShipyardView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardView, TBuildingView)

// 0x4c82c0 is a real out-of-line ctor: base ctor call, vptr store (0x651b30), then a
// single `xor eax,eax` reused for BOTH dword [this+0x94] and [this+0x98], then
// `mov eax,esi` return-this -- so zero both inherited TBuildingView fields. Zeroing only
// productionView98 left this body byte-identical to its TBuildingView siblings' ctors,
// which is what previously made the address fail to pair uniquely; with city94 stored as
// well the claim pairs at 90%.
// FUNCTION: IMPERIALISM 0x004c82c0
TShipyardView::TShipyardView() {
  city94 = 0;
  productionView98 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004c82f0
// TShipyardView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004c8320
TShipyardView::~TShipyardView() {}

// FUNCTION: IMPERIALISM 0x004c8340
void TShipyardView::Free() {
  g_pDisplayMgr->RemoveGWorld(iconSurfaceB8);
  TView::Free();
  if (g_nSaveFormatVersion != kControlTagMoil) { // 'Moil'
    g_pUiViewManager->CloseFilesFor(0x23f7);
  }
}

// Rebuilds the 8-slot ship-build queue UI: caches the strategic-map view system's
// active-view pointer and a bitmap surface for resource id 0x264f, then for each of
// eight 'but0'-'but7' queue-slot buttons clears its cached value and resets the
// button, its paired 'clu0'-'clu7' quantity cluster, and the cluster's embedded
// 'plus'/'minu' stepper controls to the disabled/off state.
// FUNCTION: IMPERIALISM 0x004c8390
void TShipyardView::DoStartup() {
  // 14-byte style buffer: the 10-byte descriptor plus 4 explicitly zeroed tail bytes.
  // Retail clears the tail at function entry and reuses the same descriptor throughout.
  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  productionView98 = g_pStrategicMapViewSystem->activeCityProductionView04;
  unresolvedZeroB4 = 0;
  iconSurfaceB8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f);

  for (int slotIndex = 0; slotIndex < 8; ++slotIndex) {
    TControl* slotButton =
        static_cast<TControl*>(ResolveControlByTag(kControlTagBut0 + slotIndex)); // 'but0'-'but7'
    slotButton->SetEnabled(0, 1);
    slotButton->SetState(0, 1);
    buildQueueSlotValues[slotIndex] = 0;

    TControl* queueSlot =
        static_cast<TControl*>(ResolveControlByTag(kControlTagClu0 + slotIndex)); // 'clu0'-'clu7'
    queueSlot->SetEnabled(0, 1);
    queueSlot->SetState(0, 1);

    TControl* plusButton =
        static_cast<TControl*>(queueSlot->ResolveControlByTag(kControlTagPlus)); // 'plus'
    plusButton->AssertValid();
    plusButton->SetState(0, 0);

    TControl* minusButton =
        static_cast<TControl*>(queueSlot->ResolveControlByTag(kControlTagMinu)); // 'minu'
    minusButton->AssertValid();
    minusButton->SetState(0, 0);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  for (short queueIndex = 0; queueIndex < 8; ++queueIndex) {
    TShipOrder* order = city94->shipOrderSlots[queueIndex];
    if (order->resourceTypeIndex != 0) {
      TOverlayRadioButton* slotButton = static_cast<TOverlayRadioButton*>(
          ResolveControlByTag(kControlTagBut0 + queueIndex)); // 'but0'-'but7'
      slotButton->SetEnabled(1, 1);
      slotButton->SetState(1, 1);

      short shipType = order->resourceTypeIndex;
      buildQueueSlotValues[queueIndex] = shipType;
      slotButton->overlaySurfaceContext98 = iconSurfaceB8;
      short sourceLeft = shipType;
      sourceLeft *= 0x50;
      sourceLeft -= 0x50;
      slotButton->overlaySrcRect9c.left = sourceLeft;
      slotButton->overlaySrcRect9c.top = 0;
      slotButton->overlaySrcRect9c.right = slotButton->overlaySrcRect9c.left + 0x50;
      slotButton->overlaySrcRect9c.bottom = 0x2d;
      slotButton->overlayDstRectAc.left = g_shipyardQueueIconLeftBySlot[queueIndex];
      slotButton->overlayDstRectAc.top = 0xc;
      slotButton->overlayDstRectAc.right = slotButton->overlayDstRectAc.left + 0x50;
      slotButton->overlayDstRectAc.bottom = 0x39;

      TControl* queueSlot = static_cast<TControl*>(
          ResolveControlByTag(kControlTagClu0 + queueIndex)); // 'clu0'-'clu7'
      queueSlot->SetEnabled(1, 1);

      TControl* plusButton =
          static_cast<TControl*>(queueSlot->ResolveControlByTag(kControlTagPlus)); // 'plus'
      plusButton->AssertValid();
      plusButton->SetState(1, 0);

      TControl* minusButton =
          static_cast<TControl*>(queueSlot->ResolveControlByTag(kControlTagMinu)); // 'minu'
      minusButton->AssertValid();
      minusButton->SetState(1, 0);

      TNumberText* quantity =
          static_cast<TNumberText*>(queueSlot->ResolveControlByTag(kControlTagNumb)); // 'numb'
      quantity->SetState(0, 0);
      quantity->SetControlValue(order->quantity, 1);
      quantity->InstallTextStyle(style.desc, 1);
    }
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0x18, 0x2b6b);
  TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl)); // 'titl'
  title->AssertValid();
  title->InstallTextStyle(style.desc, 1);
  title->SetTextFromStringResource(0x2736, 0xe, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  for (int i = 0; i < 2; ++i) {
    TStaticText* fixedLabel =
        static_cast<TStaticText*>(ResolveControlByTag(kControlTagFix0 + i)); // 'fix0'/'fix1'
    fixedLabel->AssertValid();
    fixedLabel->InstallTextStyle(style.desc, 1);
    fixedLabel->SetTextFromStringResource(0x2736, static_cast<short>(i + 0xf), 1);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TControl* shipName = static_cast<TControl*>(ResolveControlByTag(kControlTagSnam)); // 'snam'
  shipName->AssertValid();
  shipName->InstallTextStyle(style.desc, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TControl* description = static_cast<TControl*>(ResolveControlByTag(kControlTagDesc)); // 'desc'
  description->AssertValid();
  description->InstallTextStyle(style.desc, 1);

  selectedStatsRowA2 = 0;
  selectedRequirementRow = 0;
  SetShip(buildQueueSlotValues[0]);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  // 'sele' is a TCluster (confirmed by cross-referencing turn_event_dialog_factory.cpp,
  // which builds a real TCluster with controlTag 'sele'); byte 0x1c8 matches
  // TCluster::SetSelectedChildTagAndRefresh(int) exactly (1 arg, RET 4).
  TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(kControlTagSele)); // 'sele'
  sele->AssertValid();
  sele->SetSelectedChildTagAndRefresh(kControlTagBut0); // 'but0'
  UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004c8a20
void TShipyardView::LoadShipyardIconSurface() {
  iconSurfaceB8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f);
}

// FUNCTION: IMPERIALISM 0x004c8a50
void TShipyardView::UpdateFields() {
  productionView98->UpdateUnits();
  RECT refreshRect = {0x16, 0xb4, 0x124, 0xf0};
  InvalidateCityDialogRectRegion(&refreshRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c8ac0
void TShipyardView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short index = static_cast<short>(sourceHandler->controlTag) - 0x7430; // 'but0'..'but7'
    if (index >= 0 && index < 8) {
      selectedRequirementRow = index;
      SetShip(buildQueueSlotValues[index]);
    }
  } else if (commandId == 0xa) {
    TView* slotControl = static_cast<TView*>(sourceHandler)->ownerContext;
    short index = static_cast<short>(slotControl->controlTag) - 0x7530;
    if (index >= 0 && index < 8) {
      selectedRequirementRow = index;
      SetShip(buildQueueSlotValues[index]);

      TCluster* selection = static_cast<TCluster*>(ResolveControlByTag(kControlTagSele)); // 'sele'
      selection->AssertValid();
      selection->SetSelectedChildTagAndRefresh(kControlTagBut0 + index); // 'but0'+index

      TShipOrder* order = city94->shipOrderSlots[index];
      short quantity = order->quantity;
      if (sourceHandler->controlTag == kControlTagPlus) { // 'plus'
        ++quantity;
      } else {
        --quantity;
      }
      if (order->SetQuantity(quantity)) {
        TView* queueSlot = ResolveControlByTag(kControlTagClu0 + index); // 'clu0'+index
        queueSlot->AssertValid();
        TNumberText* quantityText =
            static_cast<TNumberText*>(queueSlot->ResolveControlByTag(kControlTagNumb)); // 'numb'
        quantityText->AssertValid();
        quantityText->SetControlValue(order->quantity, 0);

        CRect invalidRect;
        quantityText->QueryBounds(&invalidRect);
        OffsetRect(&invalidRect, queueSlot->ownerLocalX, queueSlot->ownerLocalY);
        queueSlot->InvalidateCityDialogRectRegion(&invalidRect, 1);

        TView* queueButton = ResolveControlByTag(kControlTagBut0 + index); // 'but0'+index
        queueButton->AssertValid();
        queueButton->RefreshControl();
        SetShip(buildQueueSlotValues[selectedRequirementRow]);
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004c8d70
void TShipyardView::SetShip(short shipType) {
  CString unusedText1;
  CString unusedText2;
  CString unusedText3;

  COLORREF savedBackgroundColor = g_pActiveQuickDrawSurfaceContext->blitSurface.backgroundColor;

  TPicture* shipPicture = static_cast<TPicture*>(ResolveControlByTag(kControlTagSpic)); // 'spic'
  shipPicture->AssertValid();
  shipPicture->SetPictureResourceIdAndRefresh(static_cast<short>(shipType + 0x266a), 1);
  g_pUiRuntimeContext->SetBackColor(0x38);

  CRect invalidRect;
  TStaticText* shipName = static_cast<TStaticText*>(ResolveControlByTag(kControlTagSnam)); // 'snam'
  if (shipName == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x408);
  }
  shipName->SetTextFromStringResource(0x2716, static_cast<short>(shipType + 1), 0);
  shipName->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TStaticText* description =
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagDesc)); // 'desc'
  description->AssertValid();
  description->SetTextFromStringResource(0x2752, shipType, 0);
  description->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  static const short kCommodityTypes[6] = {8, 9, 0x10, 0xb, 3, 0xc};
  short* costTables[6] = {g_industryActionCostWeightResCode08, g_industryActionCostWeightResCode09,
                          g_industryActionCostWeightResCode10, g_industryActionCostWeightResCode0B,
                          g_industryActionCostWeightResCode03, g_industryActionCostWeightResCode0C};
  int commodityCount = 0;
  for (int i = 0; i < 6; ++i) {
    short amount = costTables[i][shipType];
    if (amount != 0) {
      commodityRequiredAmounts[commodityCount] = amount;
      commoditySpriteIds[commodityCount] = kCommodityTypes[i];
      ++commodityCount;
    }
  }
  while (commodityCount < 4) {
    commoditySpriteIds[commodityCount++] = -1;
  }

  RECT commodityRegion = {0x19, 0x4b, 0xc4, 0xe6};
  InvalidateCityDialogRectRegion(&commodityRegion, 1);
  SetGlobalBlitTransparentColorRaw(savedBackgroundColor);
}

// Draws two dialog sections, each gated by whether it intersects the passed-in
// paint rect (SectRect): (1) the "commodities in production" icon strip -- up to 4
// commoditySpriteIds slots, each blitting the resource icon twice (rows at y=0x98 and
// y=0xcc) plus the required amount and the current stock (colored red when short); and
// (2) the selected resource's 6-column requirement metrics grid, each column a
// GetString(0x2736) header over a resource-descriptor-derived value. The original only
// initializes header-Y slots 2-5 and metric-3 values for the thirteen valid ship-type
// ids below; this source preserves that literal stack shape instead of inventing values
// for the three unused ids.
// FUNCTION: IMPERIALISM 0x004c9150
void TShipyardView::Draw(RECT* rectBuffer) {
  CString text;
  short columnHeaderY[6];
  columnHeaderY[2] = 0x56;
  columnHeaderY[3] = 0x66;
  columnHeaderY[4] = 0x76;
  columnHeaderY[5] = 0x56;
  short columnHeaderX[6] = {0x66, 0x76, 0x1c, 0x1c, 0x1c, 0x78};
  short caseThreeMetricByShipType[16];
  caseThreeMetricByShipType[1] = 0x19;
  caseThreeMetricByShipType[2] = 0;
  caseThreeMetricByShipType[4] = 0x28;
  caseThreeMetricByShipType[5] = 0x23;
  caseThreeMetricByShipType[6] = 0x41;
  caseThreeMetricByShipType[7] = 0x23;
  caseThreeMetricByShipType[9] = 0x1e;
  caseThreeMetricByShipType[10] = 0x32;
  caseThreeMetricByShipType[11] = 0x46;
  caseThreeMetricByShipType[12] = 0x2d;
  caseThreeMetricByShipType[13] = 0x28;
  caseThreeMetricByShipType[14] = 0x73;
  caseThreeMetricByShipType[15] = 0x5a;
  RECT paintRect = *rectBuffer;
  RECT drawRect;
  RECT sourceRect;
  RECT intersectionRect;
  TPicture::Draw(rectBuffer);
  UpdatePaletteIndexWithDefaultFallback(0x10);

  drawRect.left = 0x16;
  drawRect.top = 0x82;
  drawRect.right = 0xe5;
  drawRect.bottom = 0xc4;
  if (SectRect(&drawRect, &paintRect, &intersectionRect)) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
    int x = 0x3a;
    for (int slot = 0; slot < 4; ++slot) {
      short spriteId = commoditySpriteIds[slot];
      if (spriteId != -1) {
        sourceRect.left = spriteId * 0x20;
        sourceRect.top = 0;
        sourceRect.right = (spriteId + 1) * 0x20;
        sourceRect.bottom = 0x18;
        drawRect.left = x - 0x20;
        drawRect.top = 0x98;
        drawRect.right = x;
        drawRect.bottom = 0xb0;
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &sourceRect, &drawRect, 0x24, 0);
        drawRect.top = 0xcc;
        drawRect.bottom = 0xe4;
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &sourceRect, &drawRect, 0x24, 0);

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

  drawRect.left = 0x19;
  drawRect.top = 0x4b;
  drawRect.right = 0xc4;
  drawRect.bottom = 0x80;
  if (SectRect(&drawRect, &paintRect, &intersectionRect)) {
    short nCommoditySpriteId = buildQueueSlotValues[selectedRequirementRow];
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);

    for (int column = 0; column < 6; ++column) {
      g_pSimMgr->GetString(0x2736, static_cast<short>(column + 0x10), &text);
      short headerY = columnHeaderY[column];
      short headerX = columnHeaderX[column];
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
        metricValue = caseThreeMetricByShipType[nCommoditySpriteId];
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
void TShipyardView::GetCostString(CString* output, short actionIndex) {
  CString formattedAmount;
  CString resourceName;
  CString formatTemplate;
  *output = CString(g_szEmptyString);

  static const short kResourceTypes[3] = {9, 8, 0x10};
  short* costTables[3] = {g_industryActionCostWeightResCode09, g_industryActionCostWeightResCode08,
                          g_industryActionCostWeightResCode10};
  for (int i = 0; i < 3; ++i) {
    short amount = costTables[i][actionIndex];
    if (amount != 0) {
      formattedAmount.Format(g_szDecimalFormat, static_cast<int>(amount));
      g_pSimMgr->GetStringPrelude(kResourceTypes[i], &resourceName);
      g_pSimMgr->GetString(0x2738, 0x1c, &formatTemplate);
      scanBracketExpressions(g_pSimMgr, output, static_cast<LPCSTR>(formatTemplate),
                             static_cast<LPCSTR>(formattedAmount),
                             static_cast<LPCSTR>(resourceName));
    }
  }
}

// FUNCTION: IMPERIALISM 0x004c9a60
void TShipyardView::SetStats(short shipType) {
  CString shipNameText;
  CRect invalidRect;

  TStaticText* shipName = static_cast<TStaticText*>(ResolveControlByTag(kControlTagSnam)); // 'snam'
  shipName->AssertValid();
  g_pSimMgr->GetString(0x2716, shipType, &shipNameText);
  shipName->SetTextAndMaybeRefresh(&shipNameText, 0);
  shipName->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  TStaticText* history = static_cast<TStaticText*>(ResolveControlByTag(kControlTagHist)); // 'hist'
  if (history == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x410);
  }
  history->SetTextFromStringResource(0x23f7, shipType, 0);
  history->QueryBounds(&invalidRect);
  InvalidateCityDialogRectRegion(&invalidRect, 1);

  for (short statIndex = 0; statIndex < 6; ++statIndex) {
    TNumberText* stat =
        static_cast<TNumberText*>(ResolveControlByTag(kControlTagSta0 + statIndex)); // 'sta0'+index
    if (stat == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x418);
    }
    stat->SetControlValue(GetResourceDescriptorStatByColumn(shipType, statIndex), 0);
    stat->QueryBounds(&invalidRect);
    InvalidateCityDialogRectRegion(&invalidRect, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004c9d20
void TShipyardView::SetStats(TView* sourceControl) {
  short row = static_cast<short>(sourceControl->controlTag & 0xf);
  if (row != selectedStatsRowA2 && buildQueueSlotValues[row] != 0) {
    selectedStatsRowA2 = row;
    SetStats(buildQueueSlotValues[row]);
  }
}
