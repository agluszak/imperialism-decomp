#pragma once

#ifndef IMPERIALISM_CITY_ORDER_SNAPSHOTS_H
#define IMPERIALISM_CITY_ORDER_SNAPSHOTS_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CityOrderSnapshots is test-only and must not be included in the production build
#endif

class TItemOrder;
class TShipOrder;
class TTrainingOrder;
class TUnitOrder;

// What a city order and its surroundings looked like before the screen was asked to change it.
//
// The city screen scenario used to carry twenty-one loose `prior*` scalars and reuse them across
// four unrelated order families -- `priorQuantity` meant a unit order's quantity in one method, a
// ship order's in the next, a training order's in the one after that. One hundred and five
// references to a shared pile, and no way to tell locally which family a given field currently
// belonged to.
//
// Each family gets its own snapshot instead, holding only what that family's assertions read.
// `before.quantity` says what it is, two snapshots of the same type can be compared, and a field
// that belongs to ships cannot silently be read as a training order's.
//
// These are model reads only: what the order and its city hold, never what the page displays.

struct UnitOrderSnapshot {
  UnitOrderSnapshot();
  void CaptureFrom(TUnitOrder* order);

  short quantity;
  short primaryStock;
  short secondaryStock;
  short strength;
  short populationCount;
  short baselineLow;
  short baselineMedium;
  short baselineHigh;
  short productionLow;
  short productionMedium;
  short productionHigh;
  int treasury;
  float populationFloat;
};

struct ShipOrderSnapshot {
  ShipOrderSnapshot();
  void CaptureFrom(TShipOrder* order);

  short quantity;
  short shipCount;
  short merchantCapacity;
};

struct TrainingOrderSnapshot {
  TrainingOrderSnapshot();
  void CaptureFrom(TTrainingOrder* order);

  short quantity;
  short paperStock;
  short baselineLow;
  short baselineMedium;
  int treasury;
};

struct ItemOrderSnapshot {
  ItemOrderSnapshot();
  void CaptureFrom(TItemOrder* order);

  short quantity;
  short requestedQuantity;
  short primaryStock;
  short primaryTracking;
  short secondaryStock;
  short secondaryTracking;
  short reservedWorkforce;
  short productionAccum;
  short strength;
  int treasury;
};

#endif
