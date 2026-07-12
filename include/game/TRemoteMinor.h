#pragma once

#include "game/TMinor.h"

// Network multiplayer minor nation row: same layout as TMinor with a few divergent nation
// virtuals (immediate dispatch, map-cell label hook).
// VTABLE: IMPERIALISM 0x0065bde0
class TRemoteMinor : public TMinor {
public:
  DECLARE_DYNCREATE(TRemoteMinor)
  TRemoteMinor();

  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  char ShouldDispatchImmediatelySlot28(void) override;
  void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) override;

protected:
  ~TRemoteMinor() override;
};

ASSERT_SIZE(TRemoteMinor, 0x2dc);
