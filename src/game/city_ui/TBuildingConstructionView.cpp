#include "game/city_ui/TBuildingConstructionView.h"
#include "game/ui_tags_common.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city/TProductionOrder.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/gfx/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x004c9d70
// TBuildingConstructionView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c9e10
// TBuildingConstructionView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBuildingConstructionView, TPicture)

// FUNCTION: IMPERIALISM 0x004c9e30
TBuildingConstructionView::TBuildingConstructionView()
    : TPicture(), city90(0), productionView98(0) {}

// SYNTHETIC: IMPERIALISM 0x004c9e60
// TBuildingConstructionView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004c9e90
TBuildingConstructionView::~TBuildingConstructionView() {}

// FUNCTION: IMPERIALISM 0x004c9eb0
void TBuildingConstructionView::StuffValues(short buildingSlotId, TCity* city,
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
  CString capValue;
  CString capTemplate;
  CString scratch;

  this->city90 = city;
  this->buildingSlotId94 = buildingSlotId;
  this->productionView98 = productionView;

  city->GetMaxBuildingCapacity(buildingSlotId);
  this->SetPictureResourceIdAndRefresh(static_cast<short>((buildingSlotId + 0x73a) * 5), 1);

  if (buildingSlotId == 0xb) {
    city->BuildPowerPlant(0);
  } else {
    city->cityStockLumberC8 =
        static_cast<short>(city->cityStockLumberC8 + city->GetBuildingType(buildingSlotId));
    city->VerifyStocks();
    city->cityStockSteelCC =
        static_cast<short>(city->cityStockSteelCC + city->GetBuildingType(buildingSlotId));
    city->VerifyStocks();
  }

  switch (this->buildingSlotId94) {
  case 0:
  case 2:
  case 4:
  case 6:
    this->formatMode96 = 2;
    break;
  case 1:
  case 3:
  case 5:
    this->formatMode96 = 1;
    break;
  }

  // 'tex1' — headline text (string group buildingSlotId + 0x2422).
  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);
  TStaticText* tex1 =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'e', 'x', '1')));
  if (tex1 == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x47b);
  }
  tex1->InstallTextStyle(style.desc, 0);
  tex1->SetTextAlignmentAndMaybeRefresh(-2, 0);
  tex1->SetTextFromStringResource(static_cast<short>(buildingSlotId + 0x2422), 1, 1);

  // 'tex2' — sub text; string group taken from the 3rd-argument bits (see header union).
  TStaticText* tex2 =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'e', 'x', '2')));
  if (tex2 == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x481);
  }
  tex2->InstallTextStyle(style.desc, 0);
  tex2->SetTextAlignmentAndMaybeRefresh(-2, 0);
  tex2->SetTextFromStringResource(static_cast<short>(this->dialogContextFlags98), 2, 1);
  if (buildingSlotId == 0xb) {
    CRect tex2Bounds;
    tex2->QueryBounds(&tex2Bounds);
    tex2Bounds.top = tex2Bounds.top + 5;
    tex2Bounds.bottom = tex2Bounds.bottom + 5;
    tex2->ApplyBounds(&tex2Bounds, 1);
  }

  // 'name' — localized building title (string group 0x2719, indexed by slot).
  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);
  TStaticText* nameCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  if (nameCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x493);
  }
  nameCtrl->InstallTextStyle(style.desc, 0);
  nameCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
  g_pSimMgr->GetString(0x2719, buildingSlotId, &textBuffer);
  nameCtrl->SetTextAndMaybeRefresh(&textBuffer, 0);

  // 'cost' — localized cost label (string group 0x2738, index 0x14).
  TStaticText* costCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'o', 's', 't')));
  if (costCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x49a);
  }
  costCtrl->InstallTextStyle(style.desc, 0);
  costCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
  g_pSimMgr->GetString(0x2738, 0x14, &textBuffer);
  costCtrl->SetTextAndMaybeRefresh(&textBuffer, 0);

  // 'capT' — capacity value expanded into the bracket template (0x2738/0x10). Slot 11
  // uses the fixed University text (0x2738/0x15) rather than a formatted number.
  TStaticText* capTCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'a', 'p', 'T')));
  short slot = this->buildingSlotId94;
  if (slot == 0 || slot == 2 || slot == 4 || slot == 6) {
    capValue.Format(g_szDecimalFormat, 2);
  } else if (slot == 0xb) {
    g_pSimMgr->GetString(0x2738, 0x15, &capValue);
  } else {
    capValue.Format(g_szDecimalFormat, 1);
  }
  g_pSimMgr->GetString(0x2738, 0x10, &capTemplate);
  scanBracketExpressions(g_pSimMgr, &capValue, static_cast<LPCSTR>(capTemplate),
                         static_cast<LPCSTR>(capValue));
  capTCtrl->InstallTextStyle(style.desc, 0);
  capTCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
  capTCtrl->SetTextAndMaybeRefresh(&capValue, 0);

  // 'or  ' — connective label, hidden except for slots 0/3/4 where it is repositioned.
  TStaticText* orCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('o', 'r', ' ', ' ')));
  if (orCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x4b7);
  }
  if (slot != 0 && slot != 4 && slot != 3) {
    orCtrl->Show(0, 0);
  } else {
    g_pSimMgr->GetString(0x2738, 0x11, &textBuffer);
    orCtrl->InstallTextStyle(style.desc, 0);
    orCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
    orCtrl->SetTextAndMaybeRefresh(&textBuffer, 0);

    CRect orBounds;
    orCtrl->QueryBounds(&orBounds);
    short width = static_cast<short>(orBounds.right - orBounds.left);
    short height = static_cast<short>(orBounds.bottom - orBounds.top);
    short offset = 0;
    if (slot == 0) {
      offset = 0x98;
    } else if (slot == 3) {
      offset = 0xcd;
    } else if (slot == 4) {
      offset = 0xd0;
    }
    orBounds.left = offset;
    orBounds.right = offset + width;
    orBounds.bottom = orBounds.top + height;
    orCtrl->ApplyBounds(&orBounds, 0);
    orCtrl->Show(1, 0);
  }

  // 'warn' — warning text, filled in by the eligibility branch below.
  TStaticText* warnCtrl =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('w', 'a', 'r', 'n')));
  if (warnCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x4d6);
  }

  bool eligible;
  if (slot == 0xb) {
    // Power-plant slot: eligible if the owner can afford the 5000 cost; show it in 'buck'.
    CString buckCost;
    TGreatPower* owner = city->ownerNationAc;
    int availableBudget = owner->treasuryValue10 + owner->diplomacyBudgetBase / 100;
    if (availableBudget < 0) {
      availableBudget = 0;
    }
    eligible = availableBudget >= 0x1388;
    TStaticText* buckCtrl =
        static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('b', 'u', 'c', 'k')));
    buckCtrl->AssertValid();
    buckCtrl->Show(1, 0);
    buckCtrl->InstallTextStyle(style.desc, 0);
    buckCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
    g_pSimMgr->NumToCurrency(0x1388, &buckCost);
    buckCtrl->SetTextAndMaybeRefresh(&buckCost, 1);
  } else {
    // Other slots: eligible if the pending order can be raised to the missing capacity.
    TProductionOrder* order = static_cast<TProductionOrder*>(city->orderSlotsE4[slot + 0x35]);
    if (order == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x4e8);
    }
    short originalQuantity = order->quantity;
    short buildingType = static_cast<short>(city->GetBuildingType(slot));
    short needed = static_cast<short>(city->GetMaxBuildingCapacity(slot) - buildingType);
    eligible = order->SetQuantity(needed);
    order->SetQuantity(originalQuantity);
  }

  // 'okay' — enabled only when eligible; otherwise show the warning + expansion prompt.
  TPictureButton* okButton =
      static_cast<TPictureButton*>(ResolveControlByTag(IMPERIALISM_FOURCC('o', 'k', 'a', 'y')));
  okButton->AssertValid();
  if (!eligible) {
    BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b69);
    warnCtrl->InstallTextStyle(style.desc, 0);
    warnCtrl->SetTextAlignmentAndMaybeRefresh(1, 0);
    g_pSimMgr->GetString(0x2738, (slot == 0xb) ? 0x16 : 0x17, &textBuffer);
    warnCtrl->SetTextAndMaybeRefresh(&textBuffer, 0);
    warnCtrl->Show(1, 0);
    okButton->Show(0, 0);
    okButton->ViewEnable(0, 0);
  } else {
    warnCtrl->Show(0, 0);
    okButton->timingWord92 = 0xbc7;
  }
}

// FUNCTION: IMPERIALISM 0x004ca8f0
void TBuildingConstructionView::DoClosingAction(unsigned long dialogActionTag) {
  if (buildingSlotId94 != 0xb) {
    TProductionOrder* order =
        static_cast<TProductionOrder*>(city90->orderSlotsE4[buildingSlotId94 + 0x35]);
    if (order == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0x519);
    }
    if (dialogActionTag == kControlTagOkay) { // 'okay'
      short previousBuildingType = static_cast<short>(city90->GetBuildingType(buildingSlotId94));
      order->SetQuantity(static_cast<short>(city90->GetMaxBuildingCapacity(buildingSlotId94) -
                                            previousBuildingType));
    } else if (order->quantity > 0) {
      order->SetQuantity(0);
    }
  } else if (dialogActionTag == kControlTagOkay) { // 'okay'
    city90->BuildPowerPlant(1);
  }

  productionView98->SetBuildingPicture(
      buildingSlotId94, static_cast<short>(city90->GetBuildingType(buildingSlotId94)));
  productionView98->UpdateToolbar();
  productionView98->RefreshControl();
}
