#pragma once

#include "decomp_types.h"

// City/university recruitment slider commit context (body 0x004b73b0).
// `this` at the commit site is this object, not TGreatPower.
class TCityRecruitmentOrderContext {
public:
  unsigned char pad_00[0x04];
  short pendingDelta; // 0x04
  unsigned char pad_06[0x08 - 0x06];
  void* cityContext; // 0x08
  unsigned char pad_0c[0x48 - 0x0c];
  short entryId; // 0x48
  unsigned char pad_4a[0x58 - 0x4a];
  unsigned char specialistMode; // 0x58

  void CommitCityRecruitmentOrderDelta();
};
