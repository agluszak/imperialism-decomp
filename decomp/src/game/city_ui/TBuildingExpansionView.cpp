#include "game/city_ui/TBuildingExpansionView.h"
#include "game/ui_tags_common.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city/TProductionOrder.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/military/mapped_flavor_text.h"
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TBuildingExpansionView, TPicture)

// FUNCTION: IMPERIALISM 0x004ce520
TBuildingExpansionView::TBuildingExpansionView() {}

// FUNCTION: IMPERIALISM 0x004ce580
TBuildingExpansionView::~TBuildingExpansionView() {}

// FUNCTION: IMPERIALISM 0x004ce5a0
void TBuildingExpansionView::StuffValues(short buildingSlotId, TCity* city,
                                         TCityProductionView* productionView) {
  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  CString textBuffer;
  CString capacityValue;
  CString capacityTemplate;

  this->buildingSlotId = buildingSlotId;
  this->city = city;
  this->productionView = productionView;

  // Current capacity, formatted below into the 'capT' label.
  short currentCapacity = city->GetMaxBuildingCapacity(buildingSlotId);

  // Building picture = next-level tier + per-slot picture base, refreshed immediately.
  this->SetPictureRsrcID(static_cast<short>(this->city->GetNextBuildingLevel(buildingSlotId) +
                                            (buildingSlotId + 0x73a) * 5),
                         1);

  // 'name' localized building title (string group 0x2719, indexed by slot).
  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);
  TStaticText* nameCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  if (nameCtrl == nullptr) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xa78);
  }
  nameCtrl->InstallTextStyle(style.desc, 0);
  nameCtrl->SetJustification(1, false);
  g_pSimMgr->GetString(0x2719, buildingSlotId, &textBuffer);
  nameCtrl->SetTextAndMaybeRefresh(&textBuffer, false);

  // 'cost' localized label (string group 0x2738, index 0x14).
  TStaticText* costCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'o', 's', 't')));
  if (costCtrl == nullptr) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xa7f);
  }
  costCtrl->InstallTextStyle(style.desc, 0);
  costCtrl->SetJustification(1, false);
  g_pSimMgr->GetString(0x2738, 0x14, &textBuffer);
  costCtrl->SetTextAndMaybeRefresh(&textBuffer, false);

  // 'capT' capacity label: expand the bracket template (0x2738/0x10) with the numeric value.
  TStaticText* capTCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'a', 'p', 'T')));
  capacityValue.Format(g_szDecimalFormat, currentCapacity);
  g_pSimMgr->GetString(0x2738, 0x10, &capacityTemplate);
  scanBracketExpressions(g_pSimMgr, &textBuffer, static_cast<LPCSTR>(capacityTemplate),
                         static_cast<LPCSTR>(capacityValue));
  capTCtrl->InstallTextStyle(style.desc, 0);
  capTCtrl->SetJustification(1, false);
  capTCtrl->SetTextAndMaybeRefresh(&textBuffer, false);

  // 'warn' label — configured (or hidden) below depending on the upgrade-queued check.
  TStaticText* warnCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('w', 'a', 'r', 'n')));
  if (warnCtrl == nullptr) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xa95);
  }

  TProductionOrder* order = this->city->trailingOrderSlots[this->buildingSlotId + 2];
  if (order == nullptr) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xa97);
  }

  // Probe whether the full upgrade quantity is achievable, then restore the order.
  short originalQuantity = order->quantity;
  short buildingType = static_cast<short>(this->city->GetBuildingType(this->buildingSlotId));
  short needed =
      static_cast<short>(this->city->GetMaxBuildingCapacity(this->buildingSlotId) - buildingType);
  bool upgradeQueued = order->SetQuantity(needed);
  order->SetQuantity(originalQuantity);

  if (!upgradeQueued) {
    // Upgrade not queued: show the warning + expansion prompt and disable the OK button.
    BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b69);
    warnCtrl->InstallTextStyle(style.desc, 0);
    warnCtrl->SetJustification(1, false);
    g_pSimMgr->GetString(0x2738, (buildingSlotId == 0xb) ? 0x16 : 0x17, &textBuffer);
    warnCtrl->SetTextAndMaybeRefresh(&textBuffer, false);
    warnCtrl->Show(1, 0);

    TControl* okayCtrl =
        static_cast<TControl*>(ResolveControlByTag(IMPERIALISM_FOURCC('o', 'k', 'a', 'y')));
    if (okayCtrl == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xaac);
    }
    okayCtrl->Show(0, 0);
    okayCtrl->ViewEnable(0, 0);
  } else {
    // Upgrade already queued: keep the warning hidden.
    warnCtrl->Show(0, 0);
  }

  // Route the cancel button and OK button through command tag 0x22.
  TControl* cnclCtrl =
      static_cast<TControl*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'n', 'c', 'l')));
  if (cnclCtrl == nullptr) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xab7);
  }
  cnclCtrl->eventNumber = 0x22;

  TPictureButton* okButton =
      static_cast<TPictureButton*>(ResolveControlByTag(IMPERIALISM_FOURCC('o', 'k', 'a', 'y')));
  okButton->AssertValid();
  okButton->eventNumber = 0x22;
  okButton->clickSoundId = 0xbc7;
}

// FUNCTION: IMPERIALISM 0x004cebb0
void TBuildingExpansionView::DoClosingAction(unsigned long dialogActionTag) {
  TProductionOrder* order = city->trailingOrderSlots[buildingSlotId + 2];
  if (order == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0xac6);
  }
  if (dialogActionTag == kControlTagOkay) { // 'okay'
    short previousBuildingType = static_cast<short>(city->GetBuildingType(buildingSlotId));
    order->SetQuantity(
        static_cast<short>(city->GetMaxBuildingCapacity(buildingSlotId) - previousBuildingType));
  } else if (order->quantity > 0) {
    order->SetQuantity(0);
  }

  productionView->SetBuildingPicture(buildingSlotId,
                                     static_cast<short>(city->GetBuildingType(buildingSlotId)));
  productionView->UpdateToolbar();
  productionView->RefreshControl();
}
