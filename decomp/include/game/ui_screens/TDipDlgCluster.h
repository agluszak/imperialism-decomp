#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663bb0
class TDipDlgCluster : public TUberCluster {
public:
  DECLARE_DYNCREATE(TDipDlgCluster)
  virtual ~TDipDlgCluster() override;
  virtual bool IsTradeControlAtMinimum() override;

  TDipDlgCluster();
};
ASSERT_SIZE(TDipDlgCluster, 0x88);
