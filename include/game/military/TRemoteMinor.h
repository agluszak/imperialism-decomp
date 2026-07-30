#pragma once

#include "game/nation/TMinor.h"

// Network multiplayer minor nation row: same layout as TMinor with a few divergent nation
// virtuals (immediate dispatch, map-cell label hook).
// VTABLE: IMPERIALISM 0x0065bde0
class TRemoteMinor : public TMinor {
public:
  DECLARE_DYNCREATE(TRemoteMinor)
  TRemoteMinor() : TMinor() {}

  void PurchaseItem(short resourceKind, short amount, short price) override;
  bool IsRemote(void) const override;
  void PlopDownCity(short selectedRegion, const char* mapCellLabel) override;

protected:
  ~TRemoteMinor() override;
};

ASSERT_SIZE(TRemoteMinor, 0x2dc);
