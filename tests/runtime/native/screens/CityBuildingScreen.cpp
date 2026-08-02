#include "CityBuildingScreen.h"

#include "CityScreen.h"
#include "RuntimeObservations.h"
#include "RuntimeUiDriver.h"

#include "game/app/TTransFocusAnimation.h"
#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TShipOrder.h"
#include "game/city/TTrainingOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TArmoryView.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city_ui/TIndustryView.h"
#include "game/city_ui/TShipyardView.h"
#include "game/city_ui/TTradeSchoolView.h"
#include "game/city_ui/TUniversityView.h"
#include "game/core/global_data_tables.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_screens/TRadioPictureButton.h"
#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_widgets/TRailCluster.h"

namespace {

// Every production count on every building page is drawn at this size in the page's own font.
const short kCountFontSize = 10;
// Recruitment counts are drawn in the palette's highlight; the item and rail counts in black.
const unsigned long kRecruitmentCountColor = PALETTEINDEX(0xd2);
const unsigned long kProductionCountColor = PALETTEINDEX(0);

// The university offers nine recruitment categories, two of which (6 and 7) it does not show.
const short kUniversityCategoryCount = 9;
const short kUniversityHiddenCategoryA = 6;
const short kUniversityHiddenCategoryB = 7;
// The university's orders live above the armory's in the same table.
const short kUniversityOrderBase = 9;

const short kArmoryCategoryCount = 8;
const short kShipyardQueueLength = 8;

// The armory's unit pictures are consecutive pairs from this base, indexed by unit type -- except
// the last row, whose three possible units are spaced differently.
const short kArmoryPictureBase = 0x1d60;
const short kArmoryLastRow = 7;

// The trade school's trainee order.
const short kTrainingOrderSlot = 0x17;

// The unit type each industry building page produces, by building slot.
const short kIndustryUnitTypesByPage[7] = {8, 13, 11, 15, 9, 14, 12};
const short kIndustryPageCount = 7;

// The string group holding unit names, indexed one-based by unit type.
const short kUnitNameStringGroup = 0x2717;

// A quantity arrow's command, as the receiving row or cluster sees it.
const int kRaiseCommand = 100;
const int kLowerCommand = 101;

bool IsPerRowBuilding(CityBuildingKind kind) {
  return kind == kCityBuildingUniversity || kind == kCityBuildingArmory ||
         kind == kCityBuildingShipyard;
}

TGreatPower* ActiveNationState() {
  return g_pSimMgr != 0 ? g_apNationStates[g_pSimMgr->GetActiveNationId()] : 0;
}

} // namespace

CityBuildingScreen::CityBuildingScreen(short buildingSlot, CityBuildingKind buildingKind)
    : buildingView(0), slot(buildingSlot), kind(buildingKind) {
  TCityProductionView* cityView = CityScreenProductionView();
  buildingView = cityView != 0 ? cityView->BuildingViewForRuntimeTest(buildingSlot) : 0;
}

bool CityBuildingScreen::IsOpen() const {
  return buildingView != 0;
}

TBuildingView* CityBuildingScreen::View() const {
  return buildingView;
}

TCity* CityBuildingScreen::City() const {
  return buildingView != 0 ? buildingView->city94 : 0;
}

RuntimeActionResult CityBuildingScreen::MissingPage(const char* what) const {
  CString message;
  message.Format("cannot %s: building slot %d has no open production page", what,
                 static_cast<int>(slot));
  return RuntimeActionResult::Failure(message);
}

RuntimeActionResult CityBuildingScreen::PageFailure(const char* what, const CString& detail) const {
  CString message;
  message.Format("cannot %s on building slot %d: %s", what, static_cast<int>(slot),
                 static_cast<LPCSTR>(detail));
  return RuntimeActionResult::Failure(message);
}

RuntimeActionResult CityBuildingScreen::VerifyIdentity() const {
  if (buildingView == 0) {
    return MissingPage("verify the building page");
  }
  TGreatPower* player = ActiveNationState();
  if (player == 0 || buildingView->city94 != player->city) {
    return PageFailure("verify the building page",
                       CString("the page is not showing the player's own city"));
  }
  if (buildingView->isEmbeddedPage9C || buildingView->embeddedPageIndex9E != slot) {
    CString detail;
    detail.Format("the page is embedded=%d for slot %d, not the standalone page for slot %d",
                  static_cast<int>(buildingView->isEmbeddedPage9C),
                  static_cast<int>(buildingView->embeddedPageIndex9E), static_cast<int>(slot));
    return PageFailure("verify the building page", detail);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyRetailFloatingFrame() const {
  if (buildingView == 0) {
    return MissingPage("verify the building window frame");
  }
  TWindow* window = buildingView->GetWindow();
  HWND frame = window != 0 && window->nativeWindow50 != 0 ? window->nativeWindow50->m_hWnd : 0;
  if (frame == 0) {
    return PageFailure("verify the building window frame",
                       CString("the page has no native window"));
  }
  const LONG style = GetWindowLongA(frame, GWL_STYLE);
  const LONG extendedStyle = GetWindowLongA(frame, GWL_EXSTYLE);
  if (window->windowStyleType != 0x1f40 || window->windowFlags != 0x80 ||
      !window->useCaptionedFrameFlag6d || !window->topmostFlag70 ||
      (style & (WS_CAPTION | WS_SYSMENU)) != (WS_CAPTION | WS_SYSMENU) ||
      (extendedStyle & WS_EX_TOOLWINDOW) == 0) {
    CString detail;
    detail.Format("descriptor_style=0x%x descriptor_flags=0x%x caption=%d topmost=%d "
                  "style=0x%lx exstyle=0x%lx",
                  window->windowStyleType, window->windowFlags, window->useCaptionedFrameFlag6d,
                  window->topmostFlag70, style, extendedStyle);
    return PageFailure("verify the building window frame", detail);
  }
  CWnd* mainWindow = AfxGetMainWnd();
  if (mainWindow == 0 || GetParent(frame) != mainWindow->m_hWnd) {
    return PageFailure("verify the building window frame",
                       CString("the window is not owned by the main game window"));
  }
  RECT windowRect;
  POINT clientOrigin;
  clientOrigin.x = 0;
  clientOrigin.y = 0;
  if (!GetWindowRect(frame, &windowRect) || !ClientToScreen(frame, &clientOrigin) ||
      clientOrigin.y <= windowRect.top) {
    return PageFailure("verify the building window frame",
                       CString("the window has no non-client caption area"));
  }
  // Mid-caption, derived from the window's own rect: a frame that reports a caption but does not
  // hit-test as one cannot be dragged. RUNTIME_COORDINATE_EXPLAINED
  const LPARAM captionPoint =
      MAKELPARAM(static_cast<short>((windowRect.left + windowRect.right) / 2),
                 static_cast<short>((windowRect.top + clientOrigin.y) / 2));
  if (SendMessageA(frame, WM_NCHITTEST, 0, captionPoint) != HTCAPTION) {
    return PageFailure("verify the building window frame",
                       CString("the frame does not expose a movable caption"));
  }
  return RuntimeActionResult::Success();
}

TView* CityBuildingScreen::Row(short row) const {
  return buildingView != 0 ? buildingView->ResolveControlByTag(kControlTagClu0 + row) : 0;
}

TNumberText* CityBuildingScreen::RowCount(short row) const {
  // The armory keeps its counts in a parallel row of their own; the others put the count inside
  // the same cluster that carries the arrows.
  const int countRowTag =
      kind == kCityBuildingArmory ? kControlTagNum0 + row : kControlTagClu0 + row;
  TView* countRow = buildingView != 0 ? buildingView->ResolveControlByTag(countRowTag) : 0;
  TView* count = countRow != 0 ? countRow->ResolveControlByTag(kControlTagNumb) : 0;
  return count != 0 && count->IsKindOf(RUNTIME_CLASS(TNumberText)) != 0
             ? static_cast<TNumberText*>(count)
             : 0;
}

TView* CityBuildingScreen::Cluster() const {
  if (buildingView == 0) {
    return 0;
  }
  if (kind == kCityBuildingTradeSchool) {
    return buildingView->ResolveControlByTag(kSummaryTagTrai);
  }
  if (kind == kCityBuildingRailyard) {
    return buildingView->ResolveControlByTag(kSummaryTagRail);
  }
  const short unitType = IndustryUnitType();
  return unitType >= 0 ? buildingView->ResolveControlByTag(g_pTradeSummarySelectionMap[unitType])
                       : 0;
}

TView* CityBuildingScreen::ClusterArrow(bool raise) const {
  TView* cluster = Cluster();
  return cluster != 0 ? cluster->ResolveControlByTag(raise ? kControlTagRght : kControlTagLeft) : 0;
}

TNumberText* CityBuildingScreen::ClusterCount() const {
  TView* cluster = Cluster();
  TView* count = cluster != 0 ? cluster->ResolveControlByTag(kControlTagMove) : 0;
  return count != 0 && count->IsKindOf(RUNTIME_CLASS(TNumberText)) != 0
             ? static_cast<TNumberText*>(count)
             : 0;
}

short CityBuildingScreen::IndustryUnitTypeForSlot(short buildingSlot) {
  return buildingSlot >= 0 && buildingSlot < kIndustryPageCount
             ? kIndustryUnitTypesByPage[buildingSlot]
             : -1;
}

short CityBuildingScreen::IndustryUnitType() const {
  return kind == kCityBuildingIndustry ? IndustryUnitTypeForSlot(slot) : -1;
}

TUnitOrder* CityBuildingScreen::UnitOrder(short row) const {
  TCity* city = City();
  if (city == 0 || row < 0) {
    return 0;
  }
  if (kind == kCityBuildingUniversity) {
    return city->buildOrderSlots148[row + kUniversityOrderBase];
  }
  return kind == kCityBuildingArmory ? city->buildOrderSlots148[row] : 0;
}

TShipOrder* CityBuildingScreen::ShipOrder(short row) const {
  TCity* city = City();
  return city != 0 && kind == kCityBuildingShipyard && row >= 0 && row < kShipyardQueueLength
             ? city->shipOrderSlots190[row]
             : 0;
}

TTrainingOrder* CityBuildingScreen::TrainingOrder() const {
  TCity* city = City();
  return city != 0 && kind == kCityBuildingTradeSchool
             ? static_cast<TTrainingOrder*>(city->orderSlotsE4[kTrainingOrderSlot])
             : 0;
}

TItemOrder* CityBuildingScreen::ItemOrder() const {
  TCity* city = City();
  const short unitType = IndustryUnitType();
  return city != 0 && unitType >= 0 ? static_cast<TItemOrder*>(city->orderSlotsE4[unitType]) : 0;
}

TTransFocusAnimation* CityBuildingScreen::ProductionAnimation() const {
  TCityProductionView* cityView = CityScreenProductionView();
  TItemOrder* order = ItemOrder();
  return cityView != 0 && order != 0
             ? cityView->BuildingActionAnimationForRuntimeTest(order->productionSlot)
             : 0;
}

bool CityBuildingScreen::CountIsPresentedCorrectly(TNumberText* count,
                                                   unsigned long textColor) const {
  // Not editable, styled as this page's own number, positioned by its owner and given a real
  // size. A count that fails any of these was rebuilt wrongly by the refresh, whatever its
  // digits say.
  return count != 0 && count->enabled == 0 && count->viewEnabled != 0 &&
         count->stylePayload48 == 0 && count->textStyle78.fontFamily == 3 &&
         count->textStyle78.fontStyleFlags == 0 && count->textStyle78.fontSize == kCountFontSize &&
         count->textStyle78.textColor == textColor && count->ownerContext != 0 &&
         count->absoluteX == count->ownerContext->absoluteX + count->ownerLocalX &&
         count->absoluteY == count->ownerContext->absoluteY + count->ownerLocalY &&
         count->frameWidth34 > 0 && count->frameHeight38 > 0;
}

RuntimeActionResult CityBuildingScreen::CountMatchesOrder(TNumberText* count, short quantity,
                                                          unsigned long textColor,
                                                          const char* what) const {
  if (count == 0) {
    return PageFailure(what, CString("the count control is missing"));
  }
  CString shown;
  CString expected;
  count->GetCurrentText(&shown);
  expected.Format("%d", quantity);
  if (shown != expected || count->value != quantity ||
      !CountIsPresentedCorrectly(count, textColor)) {
    CString detail;
    detail.Format("text=%s expected=%s value=%d order=%d font=%d color=%lu enabled=%d",
                  static_cast<LPCSTR>(shown), static_cast<LPCSTR>(expected), count->value, quantity,
                  count->textStyle78.fontSize, count->textStyle78.textColor, count->enabled);
    return PageFailure(what, detail);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyUniversityCounts() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TUniversityView)) == 0) {
    return PageFailure("verify the university's counts",
                       CString("the slot opened the wrong view class"));
  }
  bool foundLiveCount = false;
  for (short category = 0; category < kUniversityCategoryCount; ++category) {
    if (category == kUniversityHiddenCategoryA || category == kUniversityHiddenCategoryB) {
      continue;
    }
    TNumberText* count = RowCount(category);
    if (count == 0) {
      return PageFailure("verify the university's counts",
                         CString("a recruitment count control is missing"));
    }
    // A count drawn in any other colour is a category the page is not recruiting for.
    if (count->textStyle78.textColor != kRecruitmentCountColor) {
      continue;
    }
    foundLiveCount = true;
    TUnitOrder* order = UnitOrder(category);
    if (order == 0) {
      return PageFailure("verify the university's counts",
                         CString("a live recruitment row has no order"));
    }
    RuntimeActionResult matched = CountMatchesOrder(count, order->quantity, kRecruitmentCountColor,
                                                    "verify the university's counts");
    if (!matched.Succeeded()) {
      return matched;
    }
  }
  if (!foundLiveCount) {
    return PageFailure("verify the university's counts",
                       CString("no recruitment category is live"));
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyArmoryState() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TArmoryView)) == 0) {
    return PageFailure("verify the armory's state",
                       CString("the slot opened the wrong view class"));
  }
  TArmoryView* armory = static_cast<TArmoryView*>(buildingView);
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  bool foundRaisableOrder = false;
  bool foundDifferentPicture = false;
  short firstPictureId = -1;
  for (short category = 0; category < kArmoryCategoryCount; ++category) {
    TUnitOrder* order = UnitOrder(category);
    TNumberText* count = RowCount(category);
    TView* button = buildingView->ResolveControlByTag(kControlTagCiv0 + category);
    // The armory's unit pictures are radio buttons -- picking one is what selects the unit the
    // detail panel describes. CityScreenTest read them as TCivilianButton, which is a *derived*
    // class the objects are not: the cast happened to work only because the picture id it read
    // lives on their shared TPicture base.
    if (order == 0 || count == 0 || button == 0 ||
        button->IsKindOf(RUNTIME_CLASS(TRadioPictureButton)) == 0) {
      CString detail;
      detail.Format("row %d: order=%d count=%d picture=%d picture_class=%s",
                    static_cast<int>(category), order != 0, count != 0, button != 0,
                    button != 0 ? RuntimeClassName(button) : "none");
      return PageFailure("verify the armory's state", detail);
    }

    const short unitType = order->resourceTypeIndex;
    // The row, the tech table and the ability table have to agree on which unit this row builds.
    if (g_awTacticalUnitCategoryCodeBySlot[unitType] != category + 1 ||
        g_pTechMgr->nationCapRows1e8[nationSlot].slots[category + 1] != unitType ||
        g_pTechMgr->abilityActiveRows395[nationSlot].abilityActiveById[unitType] == 0) {
      CString detail;
      detail.Format("row %d profile mismatch: type=%d category=%d selected=%d active=%d",
                    static_cast<int>(category), static_cast<int>(unitType),
                    g_awTacticalUnitCategoryCodeBySlot[unitType],
                    g_pTechMgr->nationCapRows1e8[nationSlot].slots[category + 1],
                    g_pTechMgr->abilityActiveRows395[nationSlot].abilityActiveById[unitType]);
      return PageFailure("verify the armory's state", detail);
    }

    // The last row's three units are spaced apart in the picture strip; every other row's
    // picture is its unit type.
    short pictureVariant = unitType;
    if (category == kArmoryLastRow) {
      pictureVariant = unitType == 0x18 ? 8 : (unitType == 0x19 ? 0x10 : 0x18);
    }
    const short expectedPicture = static_cast<short>(kArmoryPictureBase + pictureVariant * 2);
    const short actualPicture =
        static_cast<short>(static_cast<TRadioPictureButton*>(button)->glyphBase84 & ~1);
    if (actualPicture != expectedPicture) {
      CString detail;
      detail.Format("row %d picture mismatch: type=%d actual=%d expected=%d",
                    static_cast<int>(category), static_cast<int>(unitType),
                    static_cast<int>(actualPicture), static_cast<int>(expectedPicture));
      return PageFailure("verify the armory's state", detail);
    }
    if (category == 0) {
      firstPictureId = actualPicture;
    } else if (actualPicture != firstPictureId) {
      foundDifferentPicture = true;
    }

    RuntimeActionResult matched = CountMatchesOrder(count, order->quantity, kRecruitmentCountColor,
                                                    "verify the armory's state");
    if (!matched.Succeeded()) {
      return matched;
    }
    TView* row = Row(category);
    TView* raise = row != 0 ? row->ResolveControlByTag(kControlTagPlus) : 0;
    if (raise != 0 && raise->IsActionable() != 0 && order->MaxOrder() > order->quantity) {
      foundRaisableOrder = true;
    }
  }
  if (!foundDifferentPicture) {
    return PageFailure("verify the armory's state", CString("every unit row uses one picture"));
  }
  if (!foundRaisableOrder) {
    TUnitOrder* firstOrder = UnitOrder(0);
    TView* firstRow = Row(0);
    TView* firstRaise = firstRow != 0 ? firstRow->ResolveControlByTag(kControlTagPlus) : 0;
    CString detail;
    detail.Format("no unit order can be raised: plus=%d enabled=%d actionable=%d quantity=%d "
                  "max=%d primary_stock=%d treasury=%d",
                  firstRaise != 0, firstRaise == 0 ? -1 : firstRaise->IsEnabled(),
                  firstRaise == 0 ? -1 : firstRaise->IsActionable(), firstOrder->quantity,
                  firstOrder->MaxOrder(),
                  City()->CityStockByType(firstOrder->primaryInputResourceId),
                  City()->ownerNationAc->treasuryValue10);
    return PageFailure("verify the armory's state", detail);
  }
  if (armory->selectedUnitOrderA8 == 0) {
    return PageFailure("verify the armory's state", CString("no unit order is selected"));
  }

  // The detail panel describes the selected unit: its name comes from the string table and its
  // firepower from the retail data table, not from a placeholder.
  const short selectedUnitType = armory->selectedUnitOrderA8->resourceTypeIndex;
  TView* unitName = buildingView->ResolveControlByTag(kControlTagUnit);
  TView* firepower = buildingView->ResolveControlByTag(kControlTagSta0);
  CString expectedUnitName;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
      &expectedUnitName, kUnitNameStringGroup, static_cast<short>(selectedUnitType + 1));
  TStaticText* nameLabel = unitName != 0 && unitName->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0
                               ? static_cast<TStaticText*>(unitName)
                               : 0;
  if (nameLabel == 0 || nameLabel->text == 0 || nameLabel->text->IsEmpty() ||
      *nameLabel->text != expectedUnitName) {
    CString detail;
    detail.Format("selected unit name mismatch: control=%d text=%d type=%d", nameLabel != 0,
                  nameLabel != 0 && nameLabel->text != 0, static_cast<int>(selectedUnitType));
    return PageFailure("verify the armory's state", detail);
  }
  const int expectedFirepower = static_cast<int>(g_afArmoryUnitFirepowerByType[selectedUnitType] *
                                                 g_fArmoryFirepowerDisplayScale);
  TNumberText* firepowerField =
      firepower != 0 && firepower->IsKindOf(RUNTIME_CLASS(TNumberText)) != 0
          ? static_cast<TNumberText*>(firepower)
          : 0;
  // 999 is the placeholder the page shows when it has no data table behind it.
  if (firepowerField == 0 || firepowerField->value != expectedFirepower ||
      firepowerField->value == 999) {
    CString detail;
    detail.Format("selected unit firepower mismatch: shown=%d expected=%d",
                  firepowerField == 0 ? -1 : firepowerField->value, expectedFirepower);
    return PageFailure("verify the armory's state", detail);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyShipyardCounts() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TShipyardView)) == 0) {
    return PageFailure("verify the shipyard's counts",
                       CString("the slot opened the wrong view class"));
  }
  bool foundLiveOrder = false;
  for (short queueIndex = 0; queueIndex < kShipyardQueueLength; ++queueIndex) {
    TShipOrder* order = ShipOrder(queueIndex);
    if (order == 0 || order->resourceTypeIndex == 0) {
      continue;
    }
    foundLiveOrder = true;
    RuntimeActionResult matched =
        CountMatchesOrder(RowCount(queueIndex), order->quantity, kRecruitmentCountColor,
                          "verify the shipyard's counts");
    if (!matched.Succeeded()) {
      return matched;
    }
  }
  if (!foundLiveOrder) {
    return PageFailure("verify the shipyard's counts", CString("the build queue is empty"));
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyRailyardCount() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TIndustryView)) == 0) {
    return PageFailure("verify the railyard's count",
                       CString("the slot opened the wrong view class"));
  }
  TView* cluster = Cluster();
  TRailCluster* railCluster = cluster != 0 && cluster->IsKindOf(RUNTIME_CLASS(TRailCluster)) != 0
                                  ? static_cast<TRailCluster*>(cluster)
                                  : 0;
  if (railCluster == 0 || railCluster->selectedMetricOrder == 0) {
    return PageFailure("verify the railyard's count",
                       CString("the production cluster or its order is missing"));
  }
  return CountMatchesOrder(ClusterCount(), railCluster->selectedMetricOrder->quantity,
                           kProductionCountColor, "verify the railyard's count");
}

RuntimeActionResult CityBuildingScreen::VerifyTradeSchoolState() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TTradeSchoolView)) == 0) {
    return PageFailure("verify the trade school's state",
                       CString("the slot opened the wrong view class"));
  }
  TView* cluster = Cluster();
  TRailCluster* trainingCluster =
      cluster != 0 && cluster->IsKindOf(RUNTIME_CLASS(TRailCluster)) != 0
          ? static_cast<TRailCluster*>(cluster)
          : 0;
  TView* barView = cluster != 0 ? cluster->ResolveControlByTag(kControlTagBar) : 0;
  TAmtBar* bar = barView != 0 && barView->IsKindOf(RUNTIME_CLASS(TAmtBar)) != 0
                     ? static_cast<TAmtBar*>(barView)
                     : 0;
  TTrainingOrder* order = TrainingOrder();
  if (trainingCluster == 0 || bar == 0 || order == 0 ||
      trainingCluster->selectedMetricOrder != order || bar->auxValueA <= 0) {
    return PageFailure("verify the trade school's state",
                       CString("the trainee row has no live order or bar"));
  }
  RuntimeActionResult matched = CountMatchesOrder(
      ClusterCount(), order->quantity, kProductionCountColor, "verify the trade school's state");
  if (!matched.Succeeded()) {
    return matched;
  }
  // The bar is filled to the same fraction of its own width that the order is of the capacity.
  const short expectedBarValue =
      static_cast<short>((static_cast<int>(order->quantity) * bar->frameWidth34) / bar->auxValueA);
  if (bar->rangeOrMaxValue != expectedBarValue) {
    CString detail;
    detail.Format("bar=%d expected_bar=%d order=%d aux=%d", bar->rangeOrMaxValue, expectedBarValue,
                  order->quantity, bar->auxValueA);
    return PageFailure("verify the trade school's state", detail);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::VerifyIndustryCount() const {
  if (buildingView->IsKindOf(RUNTIME_CLASS(TIndustryView)) == 0) {
    return PageFailure("verify the industry's count",
                       CString("the slot opened the wrong view class"));
  }
  TView* cluster = Cluster();
  TIndustryCluster* industryCluster =
      cluster != 0 && cluster->IsKindOf(RUNTIME_CLASS(TIndustryCluster)) != 0
          ? static_cast<TIndustryCluster*>(cluster)
          : 0;
  TItemOrder* order = ItemOrder();
  if (industryCluster == 0 || order == 0 ||
      industryCluster->selectedMetricOrder != static_cast<TProductionOrder*>(order)) {
    return PageFailure("verify the industry's count",
                       CString("the production cluster is missing or shows another order"));
  }
  return CountMatchesOrder(ClusterCount(), order->quantity, kProductionCountColor,
                           "verify the industry's count");
}

RuntimeActionResult CityBuildingScreen::VerifyLiveOrderState() const {
  if (buildingView == 0) {
    return MissingPage("verify the building's counts");
  }
  switch (kind) {
  case kCityBuildingUniversity:
    return VerifyUniversityCounts();
  case kCityBuildingArmory:
    return VerifyArmoryState();
  case kCityBuildingShipyard:
    return VerifyShipyardCounts();
  case kCityBuildingRailyard:
    return VerifyRailyardCount();
  case kCityBuildingTradeSchool:
    return VerifyTradeSchoolState();
  default:
    break;
  }
  return VerifyIndustryCount();
}

short CityBuildingScreen::FirstRaisableRow() const {
  if (buildingView == 0 || !IsPerRowBuilding(kind)) {
    return -1;
  }
  const short rowCount = kind == kCityBuildingUniversity ? kUniversityCategoryCount
                         : kind == kCityBuildingArmory   ? kArmoryCategoryCount
                                                         : kShipyardQueueLength;
  for (short row = 0; row < rowCount; ++row) {
    if (kind == kCityBuildingUniversity &&
        (row == kUniversityHiddenCategoryA || row == kUniversityHiddenCategoryB)) {
      continue;
    }
    TProductionOrder* order = kind == kCityBuildingShipyard
                                  ? static_cast<TProductionOrder*>(ShipOrder(row))
                                  : static_cast<TProductionOrder*>(UnitOrder(row));
    if (order == 0 || order->MaxOrder() <= order->quantity) {
      continue;
    }
    // An empty shipyard queue slot has a row but nothing to build in it.
    if (kind == kCityBuildingShipyard && ShipOrder(row)->resourceTypeIndex == 0) {
      continue;
    }
    TView* rowView = Row(row);
    TView* raise = rowView != 0 ? rowView->ResolveControlByTag(kControlTagPlus) : 0;
    if (raise != 0 && raise->IsActionable() != 0 && raise->IsEnabled() != 0) {
      return row;
    }
  }
  return -1;
}

namespace {

RuntimeActionResult ActivateRowControl(TView* row, int tag, const char* what) {
  if (row == 0) {
    CString message;
    message.Format("cannot %s: the row is not present", what);
    return RuntimeActionResult::Failure(message);
  }
  CString failure;
  if (!RuntimeUiDriver::Activate(row, RuntimeControlSelector(tag, RUNTIME_CLASS(TControl)),
                                 &failure)) {
    CString message;
    message.Format("cannot %s: %s", what, static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  return RuntimeActionResult::Success();
}

} // namespace

RuntimeActionResult CityBuildingScreen::RaiseRow(short row) {
  return ActivateRowControl(Row(row), kControlTagPlus, "raise a production order");
}

RuntimeActionResult CityBuildingScreen::LowerRow(short row) {
  return ActivateRowControl(Row(row), kControlTagMinu, "lower a production order");
}

namespace {

// The two cluster buildings differ in who handles the arrow's command: the trade school's arrow
// handles its own, the industries' cluster handles the arrow's. Sending it to the wrong one is
// silently ignored, so this is not interchangeable.
RuntimeActionResult SendArrowCommand(CityBuildingKind kind, TView* cluster, TView* arrow,
                                     int command, const char* what) {
  if (cluster == 0 || arrow == 0) {
    CString message;
    message.Format("cannot %s: the cluster or its arrow is not present", what);
    return RuntimeActionResult::Failure(message);
  }
  if (arrow->IsActionable() == 0) {
    CString message;
    message.Format("cannot %s: the arrow is not actionable", what);
    return RuntimeActionResult::Failure(message);
  }
  TView* receiver = kind == kCityBuildingTradeSchool ? arrow : cluster;
  receiver->HandleEvent(command, arrow, 0);
  return RuntimeActionResult::Success();
}

} // namespace

RuntimeActionResult CityBuildingScreen::RaiseClusterOrder() {
  return SendArrowCommand(kind, Cluster(), ClusterArrow(true), kRaiseCommand,
                          "raise the production order");
}

RuntimeActionResult CityBuildingScreen::LowerClusterOrder() {
  return SendArrowCommand(kind, Cluster(), ClusterArrow(false), kLowerCommand,
                          "lower the production order");
}

RuntimeActionResult CityBuildingScreen::RefreshClusterAmount() {
  TView* cluster = Cluster();
  TTrainingOrder* order = TrainingOrder();
  if (cluster == 0 || cluster->IsKindOf(RUNTIME_CLASS(TRailCluster)) == 0 || order == 0) {
    return MissingPage("refresh the trainee cluster");
  }
  static_cast<TRailCluster*>(cluster)->SetMoveAmount(order->quantity, 1);
  return RuntimeActionResult::Success();
}

RuntimeActionResult CityBuildingScreen::CloseNatively() {
  if (buildingView == 0) {
    return MissingPage("close the building window");
  }
  TWindow* window = buildingView->GetWindow();
  HWND frame = window != 0 && window->nativeWindow50 != 0 ? window->nativeWindow50->m_hWnd : 0;
  if (frame == 0) {
    return PageFailure("close the building window", CString("the page has no native window"));
  }
  // The window's own system close, which is the path a player takes.
  SendMessageA(frame, WM_SYSCOMMAND, SC_CLOSE, 0);
  return RuntimeActionResult::Success();
}
