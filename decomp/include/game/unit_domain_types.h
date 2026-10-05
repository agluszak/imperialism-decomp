#pragma once

enum UnitOrder {
  kUnitOrderIdle = 0,
  kUnitOrderRedeploy = 1,
  kUnitOrderSleep = 2,
  kUnitOrderLayRail = 5,
  kUnitOrderBuildDepot = 6,
  kUnitOrderBuildPort = 7,
  kUnitOrderProspect = 8,
  kUnitOrderDevelopResource = 10,
  kUnitOrderBuildFort = 12,
  kUnitOrderPurchaseLand = 13
};

typedef short UnitOrderStorage;

inline UnitOrder DecodeUnitOrder(UnitOrderStorage storedOrder) {
  return static_cast<UnitOrder>(storedOrder);
}

inline UnitOrderStorage EncodeUnitOrder(UnitOrder order) {
  return static_cast<UnitOrderStorage>(order);
}
