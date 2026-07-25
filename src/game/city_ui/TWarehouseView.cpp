#include "game/city_ui/TWarehouseView.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/gfx/CDib.h"
#include "game/military/mapped_flavor_text.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_widgets/TPictureNumberText.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x004c71f0
// TWarehouseView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c7290
// TWarehouseView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWarehouseView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004c72b0
TWarehouseView::TWarehouseView() : TBuildingView() {}

// SYNTHETIC: IMPERIALISM 0x004c72e0
// TWarehouseView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004c7310
TWarehouseView::~TWarehouseView() {}

// FUNCTION: IMPERIALISM 0x004c7330
void TWarehouseView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  TControl::DoMouseCommand(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004c7360
void TWarehouseView::DoStartup() {
  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  CString hoverText;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);

  // 'name' -- the warehouse title label.
  TStaticText* name =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  name->InstallTextStyle(style.desc, 0);
  name->SetTextAlignmentAndMaybeRefresh(1, 0);
  g_pSimMgr->GetString(0x2719, 0xd, &hoverText);
  name->SetTextAndMaybeRefresh(&hoverText, 0);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);

  // Resolve and style the 23 commodity value controls by their FourCC tags.
  const int* commodityTag = g_pTradeSummarySelectionMap;
  TPictureNumberText** commodityControl = commodityValueControlsA0;
  int commodityCount = 23;
  do {
    TStaticText* control = static_cast<TStaticText*>(ResolveControlByTag(*commodityTag));
    *commodityControl = static_cast<TPictureNumberText*>(control);
    if (control != nullptr) {
      control->InstallTextStyle(style.desc, 0);
      control->SetTextAlignmentAndMaybeRefresh(1, 0);
    }
    ++commodityTag;
    ++commodityControl;
    --commodityCount;
  } while (commodityCount != 0);

  // 'labo' -- labor value control.
  laborValueControlFC =
      static_cast<TPictureNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('l', 'a', 'b', 'o')));
  if (laborValueControlFC != nullptr) {
    laborValueControlFC->InstallTextStyle(style.desc, 0);
    laborValueControlFC->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  // 'powe' -- power value control.
  powerValueControl100 =
      static_cast<TPictureNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'o', 'w', 'e')));
  if (powerValueControl100 != nullptr) {
    powerValueControl100->InstallTextStyle(style.desc, 0);
    powerValueControl100->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  if (g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] != 0) {
    TWindow* window = GetWindow();
    CRect windowBounds;
    window->QueryBounds(&windowBounds);

    commodityValueControlsA0[6]->SetEnabled(1, 1);
    commodityValueControlsA0[12]->SetEnabled(1, 1);
    powerValueControl100->SetEnabled(1, 1);
    SetPictureResourceIdAndRefresh(0x23ff, 1);

    CPoint bitmapSize;
    cachedBitmap->CopyBitmapDimensionsToPoint(&bitmapSize);
    CRect expandedBounds(windowBounds.left, windowBounds.top, windowBounds.left + bitmapSize.x,
                         windowBounds.top + bitmapSize.y);
    window->ApplyBounds(&expandedBounds, 1);

    CRect pictureBounds(0, 0, bitmapSize.x, bitmapSize.y);
    ApplyBounds(&pictureBounds, 0);

    unsigned int shiftedControlTags[6] = {
        IMPERIALISM_FOURCC('h', 'o', 'r', 's'), IMPERIALISM_FOURCC('f', 'o', 'o', 'd'),
        IMPERIALISM_FOURCC('l', 'a', 'b', 'o'), IMPERIALISM_FOURCC('g', 'r', 'a', 'i'),
        IMPERIALISM_FOURCC('p', 'r', 'o', 'd'), IMPERIALISM_FOURCC('l', 'i', 'v', 'e'),
    };
    unsigned int* shiftedTag = shiftedControlTags;
    int shiftedCount = 6;
    do {
      TView* shiftedControl = ResolveControlByTag(*shiftedTag);
      CRect shiftedBounds;
      shiftedControl->QueryBounds(&shiftedBounds);
      shiftedBounds.top += static_cast<short>(bitmapSize.x);
      shiftedBounds.bottom += static_cast<short>(bitmapSize.x);
      shiftedControl->ApplyBounds(&shiftedBounds, 0);
      ++shiftedTag;
      --shiftedCount;
    } while (shiftedCount != 0);
  }

  int hoverSize[2] = {0x20, 0x18};
  TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  CString hoverTemplate;
  CString commodityName;
  CString valueText;
  SetControlHoverHelpText(CString(g_szEmptyString), this);
  g_pSimMgr->GetString(0x2734, 0x20, &hoverTemplate);

  short commodity = 0;
  TPictureNumberText** valueControlPtr = commodityValueControlsA0;
  do {
    TPictureNumberText* valueControl = *valueControlPtr;
    if (valueControl != 0 && valueControl->field08 != 0) {
      int hoverOrigin[2] = {valueControl->ownerLocalX - 0xf, valueControl->ownerLocalY - 0x14};
      TView* hoverControl = new TView();
      hoverControl->InitializeUiResourceEntryFrameAndParent(0, this, hoverOrigin, hoverSize, 5, 5,
                                                            0);

      switch (commodity) {
      case 7:
      case 16:
        g_pSimMgr->GetStringPrelude(commodity, &hoverText);
        break;
      case 17:
      case 18:
        valueText.Format(g_szDecimalFormat, nation->GetNeedTargetByType(commodity));
        g_pSimMgr->GetStringPrelude(commodity, &commodityName);
        scanBracketExpressions(g_pSimMgr, &hoverText, static_cast<LPCSTR>(hoverTemplate),
                               static_cast<LPCSTR>(commodityName), static_cast<LPCSTR>(valueText));
        break;
      case 19:
      case 21:
      case 22:
        break;
      case 20: {
        int needTotal = nation->GetNeedTargetByType(20);
        needTotal += nation->GetNeedTargetByType(19);
        valueText.Format(g_szDecimalFormat, needTotal);
        g_pSimMgr->GetString(0x2734, 0x1f, &commodityName);
        scanBracketExpressions(g_pSimMgr, &hoverText, static_cast<LPCSTR>(hoverTemplate),
                               static_cast<LPCSTR>(commodityName), static_cast<LPCSTR>(valueText));
        CRect hoverBounds;
        hoverControl->QueryBounds(&hoverBounds);
        hoverBounds.left -= 0x28;
        hoverControl->ApplyBounds(&hoverBounds, 1);
        break;
      }
      default:
        g_pSimMgr->GetStringPrelude(commodity, &commodityName);
        valueText.Format(g_szDecimalFormat, nation->GetNeedTargetByType(commodity));
        scanBracketExpressions(g_pSimMgr, &hoverText, static_cast<LPCSTR>(hoverTemplate),
                               static_cast<LPCSTR>(commodityName), static_cast<LPCSTR>(valueText));
        break;
      }
      SetControlHoverHelpText(hoverText, hoverControl);
    }
    ++commodity;
    ++valueControlPtr;
  } while (commodity < 23);

  if (laborValueControlFC != 0) {
    int hoverOrigin[2] = {laborValueControlFC->ownerLocalX - 0xf,
                          laborValueControlFC->ownerLocalY - 0x14};
    TView* hoverControl = new TView();
    hoverControl->InitializeUiResourceEntryFrameAndParent(0, this, hoverOrigin, hoverSize, 5, 5, 0);
    g_pSimMgr->GetString(0x2734, 0x22, &hoverText);
    SetControlHoverHelpText(hoverText, hoverControl);
  }

  if (powerValueControl100 != 0 && powerValueControl100->field08 != 0) {
    int hoverOrigin[2] = {powerValueControl100->ownerLocalX - 0xf,
                          powerValueControl100->ownerLocalY - 0x14};
    TView* hoverControl = new TView();
    hoverControl->InitializeUiResourceEntryFrameAndParent(0, this, hoverOrigin, hoverSize, 5, 5, 0);
    g_pSimMgr->GetString(0x2734, 0x21, &hoverText);
    SetControlHoverHelpText(hoverText, hoverControl);
  }
}

// FUNCTION: IMPERIALISM 0x004c7d90
void TWarehouseView::UpdateFields() {
  for (short commodity = 0; commodity < 23; ++commodity) {
    TPictureNumberText* valueControl = commodityValueControlsA0[commodity];
    if (valueControl != 0) {
      short amount = city94->CityStockByType(commodity);
      if (valueControl->UpdateControlCachedIntFromWindowText() != amount) {
        if (commodity == 20) {
          amount = static_cast<short>(city94->cityStockFishDC + city94->cityStockLivestockDE);
          valueControl = commodityValueControlsA0[commodity];
        }
        valueControl->SetControlValue(amount, 1);
      }
    }
  }

  if (laborValueControlFC != 0) {
    short labor = city94->productionSummary1d8->strength;
    if (laborValueControlFC->UpdateControlCachedIntFromWindowText() != labor) {
      laborValueControlFC->SetControlValue(labor, 1);
    }
  }

  if (powerValueControl100 != 0) {
    short power = city94->powerAvailableB4;
    if (powerValueControl100->UpdateControlCachedIntFromWindowText() != power) {
      powerValueControl100->SetControlValue(power, 1);
    }
  }
}
