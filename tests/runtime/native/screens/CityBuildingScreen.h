#pragma once

#ifndef IMPERIALISM_CITY_BUILDING_SCREEN_H
#define IMPERIALISM_CITY_BUILDING_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CityBuildingScreen is test-only and must not be included in the production build
#endif

#include "RuntimeActionResult.h"

class TBuildingView;
class TCity;
class TItemOrder;
class TShipOrder;
class TTrainingOrder;
class TTransFocusAnimation;
class TUnitOrder;

// Which building a city page is. Two of them (the railyard and the industries) are the same view
// class, so the kind cannot be recovered from the page alone -- the slot it was opened from is
// what distinguishes them, and the caller knows that.
enum CityBuildingKind {
  kCityBuildingUniversity,
  kCityBuildingArmory,
  kCityBuildingShipyard,
  kCityBuildingRailyard,
  kCityBuildingTradeSchool,
  kCityBuildingIndustry
};

// One building's production page, opened as a floating window over the city screen.
//
// The six buildings show the same idea -- an order, a count, and a way to raise and lower it --
// through four different control shapes: per-row plus/minus buttons (university, armory,
// shipyard), a single cluster with side arrows whose command the *arrow* handles (the trade
// school), and one whose command the *cluster* handles (the industries). CityScreenTest carried
// all four inline, along with 330 lines of "does this label agree with the order behind it".
//
// The agreement checks return a RuntimeActionResult rather than a bool so their detail -- which
// row, which value, what was expected -- survives to the scenario's failure message.
class CityBuildingScreen {
public:
  CityBuildingScreen(short buildingSlot, CityBuildingKind kind);

  bool IsOpen() const;
  TBuildingView* View() const;
  TCity* City() const;

  // The page is this slot's own standalone window, for the player's own city.
  RuntimeActionResult VerifyIdentity() const;
  // Its native frame is the retail floating tool window: captioned, topmost, owned by the main
  // game window, and with a caption area the player could actually drag it by.
  RuntimeActionResult VerifyRetailFloatingFrame() const;
  // Every count on the page agrees with the live order behind it. What that means depends on
  // the building.
  RuntimeActionResult VerifyLiveOrderState() const;

  // The orders behind the rows, by building. The scenario snapshots model state through these,
  // so they are the page's own view of what it is showing.
  TUnitOrder* UnitOrder(short row) const;
  TShipOrder* ShipOrder(short row) const;
  TTrainingOrder* TrainingOrder() const;
  TItemOrder* ItemOrder() const;
  // The industry page's building animation, which a production order starts and a cancelled one
  // stops.
  TTransFocusAnimation* ProductionAnimation() const;
  // The resource an industry building produces, or -1 for the other kinds.
  short IndustryUnitType() const;
  // Usable before the page is open, for a caller choosing which industry to visit.
  static short IndustryUnitTypeForSlot(short buildingSlot);

  // A row whose order can still be raised, or -1. Only the per-row buildings have rows; the
  // trade school and the industries have one cluster, so their arrows take no row.
  short FirstRaisableRow() const;
  RuntimeActionResult RaiseRow(short row);
  RuntimeActionResult LowerRow(short row);
  RuntimeActionResult RaiseClusterOrder();
  RuntimeActionResult LowerClusterOrder();
  // Push a completed order's new quantity back into the cluster, which is what the retail
  // completion path does before the bar is next drawn.
  RuntimeActionResult RefreshClusterAmount();

  // Close through the window's own system menu, as a player would.
  RuntimeActionResult CloseNatively();

private:
  RuntimeActionResult PageFailure(const char* what, const CString& detail) const;
  RuntimeActionResult MissingPage(const char* what) const;

  class TView* Row(short row) const;
  class TNumberText* RowCount(short row) const;
  class TView* Cluster() const;
  class TView* ClusterArrow(bool raise) const;
  class TNumberText* ClusterCount() const;

  RuntimeActionResult VerifyUniversityCounts() const;
  RuntimeActionResult VerifyArmoryState() const;
  RuntimeActionResult VerifyShipyardCounts() const;
  RuntimeActionResult VerifyRailyardCount() const;
  RuntimeActionResult VerifyTradeSchoolState() const;
  RuntimeActionResult VerifyIndustryCount() const;

  // A count control the page refreshed: not editable, styled as the page's own number, drawn
  // where its owner puts it and with a real size. A count that fails this is one the refresh
  // rebuilt wrongly even if its digits happen to match.
  bool CountIsPresentedCorrectly(class TNumberText* count, unsigned long textColor) const;
  // The digits, the cached value and the order all agree.
  RuntimeActionResult CountMatchesOrder(class TNumberText* count, short quantity,
                                        unsigned long textColor, const char* what) const;

  TBuildingView* buildingView;
  short slot;
  CityBuildingKind kind;
};

#endif
