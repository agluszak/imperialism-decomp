#pragma once

// Legacy view structs retained for field-offset casts in TGreatPower.cpp.
// The polymorphic TNationState shim is retired — use TGreatPower / TMinor.

struct TSecondaryNationStateOwner {
  unsigned char pad00[0x0C];
  short fallbackNationSlot;
  short encodedOwnerNationSlot;
};

struct TNationStateFlags {
  unsigned char pad00[0xA0];
  char busyFlagA0;
};

// Event-message eligibility bytes at +0x4c/+0x4d live on TTown records
// (transportLinkedFlag4c / enabledFlag4d), not on nation-state objects.
