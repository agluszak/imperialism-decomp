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
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void NoOpUiLifecycleHook(int styleSeed) override;
  virtual void ApplyMoveValue(int value) override;
};

ASSERT_SIZE(TShipyardCluster, 0x90);

TShipyardCluster* __cdecl CreateTradeMoveArrowControlPanel(void);
