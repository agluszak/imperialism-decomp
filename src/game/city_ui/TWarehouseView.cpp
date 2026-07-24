#include "game/city_ui/TWarehouseView.h"
#include "game/city/TCity.h"
#include "game/ui_widgets/TPictureNumberText.h"
#include "game/city/TPopulationMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_text_label_helpers_decls.h"
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
  TBuildingView::DoStartup();

  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);

  // 'name' -- the warehouse title label.
  TStaticText* name =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  if (name != nullptr) {
    name->InstallTextStyle(style.desc, 0);
    name->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);

  // Resolve and style the 23 commodity value controls by their FourCC tags.
  for (short i = 0; i < 23; ++i) {
    TStaticText* control =
        static_cast<TStaticText*>(ResolveControlByTag(g_pTradeSummarySelectionMap[i]));
    commodityValueControlsA0[i] = static_cast<TPictureNumberText*>(control);
    if (control != nullptr) {
      control->InstallTextStyle(style.desc, 0);
      control->SetTextAlignmentAndMaybeRefresh(1, 0);
    }
  }

  // 'labo' -- labor value control.
  TStaticText* labor =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('l', 'a', 'b', 'o')));
  laborValueControlFC = static_cast<TPictureNumberText*>(labor);
  if (labor != nullptr) {
    labor->InstallTextStyle(style.desc, 0);
    labor->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  // 'powe' -- power value control.
  TStaticText* power =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'o', 'w', 'e')));
  powerValueControl100 = static_cast<TPictureNumberText*>(power);
  if (power != nullptr) {
    power->InstallTextStyle(style.desc, 0);
    power->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  UpdateFields();
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
