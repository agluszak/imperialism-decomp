#pragma once

#include "game/TMinor.h"

// Network multiplayer minor nation row: same nation prefix as TMinor with remote-only
// tail state and a few divergent nation virtuals (immediate dispatch, map-cell label hook).
// VTABLE: IMPERIALISM 0x0065bde0
class TRemoteMinor : public TMinor {
public:
  TRemoteMinor();

  static void* AllocateAndConstructTRemoteMinor();
  static void* GetTRemoteMinorClassNamePointer();

  CRuntimeClass* GetRuntimeClass() const override;

  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  char ShouldDispatchImmediatelySlot28(void) override;
  void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) override;

protected:
  ~TRemoteMinor();

private:
  unsigned char remoteMinorTail[0x2dc - 0x2cc];
};

ASSERT_SIZE(TRemoteMinor, 0x2dc);

