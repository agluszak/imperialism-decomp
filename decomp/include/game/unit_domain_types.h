#pragma once

// Shared TUnit order state. Mac CodeWarrior signatures name this domain UnitOrder
// on TUnit::SetOrders, TCivUnit::SetOrders, and TArmyMgr::OrderSelectedArmies.
// The Windows base field and virtual parameter are dwords, so a VC5 classic enum
// preserves their layout and ABI. Values 2, 3, 4, 9, 11, and 14 remain unnamed
// until their military/civilian behavior is recovered from all consumers.
enum UnitOrder {
  kUnitOrderIdle = 0,
  kUnitOrderRedeploy = 1,
  kUnitOrderLayRail = 5,
  kUnitOrderBuildDepot = 6,
  kUnitOrderBuildPort = 7,
  kUnitOrderProspect = 8,
  kUnitOrderDevelopResource = 10,
  kUnitOrderBuildFort = 12,
  kUnitOrderPurchaseLand = 13
};

// A few listing-proven helper boundaries pass the order as a signed word even
// though TUnit stores it as a dword. Keep the narrowing at those boundaries.
typedef short UnitOrderStorage;

inline UnitOrder DecodeUnitOrder(UnitOrderStorage storedOrder) {
  return static_cast<UnitOrder>(storedOrder);
}

inline UnitOrderStorage EncodeUnitOrder(UnitOrder order) {
  return static_cast<UnitOrderStorage>(order);
}
