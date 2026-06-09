#pragma once

// Legacy view structs retained for field-offset casts in TGreatPower.cpp.
// The polymorphic TNationState shim is retired — use TGreatPower / TSecondaryNationState.

struct TSecondaryNationStateOwner {
  unsigned char pad00[0x0C];
  short fallbackNationSlot;
  short encodedOwnerNationSlot;
};

struct TNationStateFlags {
  unsigned char pad00[0xA0];
  char busyFlagA0;
};

struct TNationStateEventMessageFlags {
  unsigned char pad00[0x4C];
  unsigned char suppressEventMessage4C;
  unsigned char allowEventMessage4D;
};
