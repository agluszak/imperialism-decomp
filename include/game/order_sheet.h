#pragma once

// OrderSheet: the buffer passed to the TProductionOrder::FillOrderSheet/CanFillOrderSheet
// family (TProductionOrder, TItemOrder, TExpansionOrder, TUnitOrder, TPowerPlantOrder,
// TPopGrowthOrder, TFoodProcessingOrder, TTrainingOrder, TShipOrder/TCapacityOrder).
//
// Evidence for the layout: every FillOrderSheet/CanFillOrderSheet override reads/writes
// this buffer at a 2-byte-aligned offset that is always `resourceCode * 2` -- both as a
// literal constant (e.g. WriteShort(orderSheet, 0x16, ...) for weight code 0x0B) and,
// in TExpansionOrder/TItemOrder/TUnitOrder, as an explicit runtime multiply
// (`this->primaryInputResourceId * 2`). That makes the sheet a flat
// per-resource-code array of shorts, matching the sibling `TProductionOrder::
// trackingSlots10` array (same offset range 0x10..0x3e, same resource-code indexing) --
// i.e. the order-sheet and the order's own tracking slots share one indexing scheme.
//
// Total size is evidence-backed (not guessed): TProductionOrder::ResetOrderSheet
// (0x004b5180, the shared "clear the sheet" body) zeroes exactly 0x1e dwords (offsets 0x00..0x77) then three
// more trailing shorts at 0x78/0x7a/0x7c, i.e. 0x7e bytes = 0x3f shorts (indices 0..62),
// entry-for-entry via one loop plus three explicit statements for the remainder that
// doesn't divide evenly into dwords -- not evidence that 0x78/0x7a/0x7c are a
// semantically distinct trailer, just that the clear loop is dword-granular. Modeled as
// one uniform array through index 62.
//
// NOT YET VERIFIED: the real allocator/caller. Every xref to a FillOrderSheet override
// resolves only to the vtable slot (address-taken data); the code that allocates this
// buffer and loops over a city's order items to fill it hasn't been located, so there is
// deliberately no ASSERT_SIZE here (0x7e is corroborated by Produce()'s clear loop, but
// not by a verified allocation site).
struct OrderSheet {
  short slotByResourceCode[0x3f];

  short& ForResourceCode(int resourceCode) {
    return slotByResourceCode[resourceCode];
  }
};
