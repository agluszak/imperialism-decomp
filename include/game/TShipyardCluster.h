#pragma once

#include "compat.h"
#include "game/TUberCluster.h"

struct CRuntimeClass;
class TAmtBar;

// VTABLE: IMPERIALISM 0x666760
class TShipyardCluster : public TUberCluster {
public:
  int field_88;
  short field_8c;
  short field_8e;

  TShipyardCluster();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor from TUberCluster).

  virtual void ApplyMoveValue(int value) override;

  void SelectTradeSpecialCommodityAndInitializeControls();
  void HandleTradeMoveArrowControlEvent(int commandId, TAmtBar* sourceControl, int eventExtra);
};

ASSERT_SIZE(TShipyardCluster, 0x90);

TShipyardCluster* __cdecl CreateTradeMoveArrowControlPanel(void);
