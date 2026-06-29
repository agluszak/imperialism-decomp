#include "game/TCityOrderItem.h"

#include "decomp_types.h"
#include "game/mfc.h"

// Slot 0x3c (Mac: Produce). The real body at 0x004b5180 is owned by
// TProductionOrder (its own vtable region); this parallel TCityOrderItem chain
// (TCapacityOrder) shares the same slot but cannot own the address, so this is an
// unmarked stub. Direct callers (TCapacityOrder::...) still resolve to it.
void TCityOrderItem::Produce(void* orderSheet) {
  undefined4* cursor = static_cast<undefined4*>(orderSheet);
  int remaining = 0x1e;
  while (remaining != 0) {
    *cursor = 0;
    cursor = cursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(cursor) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(orderSheet) + 0x7a) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(orderSheet) + 0x7c) = 0;
}

short TCityOrderItem::MaxOrder() {
  return 0;
}

bool TCityOrderItem::SetQuantity(short quantity) {
  (void)quantity;
  return false;
}

void TCityOrderItem::CommitIfPending() {}

void TCityOrderItem::FillOrderSheet(void* orderSheet, short quantity) {
  (void)orderSheet;
  (void)quantity;
}

bool TCityOrderItem::CanMakeFromCityStock() {
  return false;
}

bool TCityOrderItem::CanFillOrderSheet(void* orderSheet) {
  (void)orderSheet;
  return false;
}

void TCityOrderItem::ApplyCityProductionSlotDelta() {}
