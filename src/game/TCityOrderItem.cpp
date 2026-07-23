#include "game/TCityOrderItem.h"

#include "decomp_types.h"
#include "game/mfc.h"

// Slot 0x3c (Mac: Produce). The real body at 0x004b5180 is owned by
// TProductionOrder (its own vtable region); this parallel TCityOrderItem chain
// (TCapacityOrder) shares the same slot but cannot own the address, so this is an
// unmarked stub. Direct callers (TCapacityOrder::...) still resolve to it.
void TCityOrderItem::Produce(OrderSheet* orderSheet) {
  for (int resourceCode = 0; resourceCode < 0x3f; ++resourceCode) {
    orderSheet->slotByResourceCode[resourceCode] = 0;
  }
}

short TCityOrderItem::MaxOrder() {
  return 0;
}

bool TCityOrderItem::SetQuantity(short quantity) {
  (void)quantity;
  return false;
}

void TCityOrderItem::CommitIfPending() {}

void TCityOrderItem::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  (void)orderSheet;
  (void)quantity;
}

bool TCityOrderItem::CanMakeFromCityStock() {
  return false;
}

bool TCityOrderItem::CanFillOrderSheet(OrderSheet* orderSheet) {
  (void)orderSheet;
  return false;
}

void TCityOrderItem::ApplyCityProductionSlotDelta() {}
