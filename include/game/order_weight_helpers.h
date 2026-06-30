#pragma once

// Shared inline helpers and constants for city-order weight lookups.
// Used by TCapacityOrder and TShipOrder.

enum {
  kResourceWeightIndex03 = 3,
  kResourceWeightIndex08 = 8,
  kResourceWeightIndex09 = 9,
  kResourceWeightIndex0B = 11,
  kResourceWeightIndex0C = 12,
  kResourceWeightIndex10 = 16,
};

static __inline short ReadWeight(const short* tableBase, short index) {
  return tableBase[static_cast<unsigned int>(index)];
}

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

static __inline short ReadShort(void* base, int offset) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset);
}
