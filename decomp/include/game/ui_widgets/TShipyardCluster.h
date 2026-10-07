#pragma once

#include "compat.h"
#include "game/ui_widgets/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TShipOrder;

// VTABLE: IMPERIALISM 0x666760
class TShipyardCluster : public TAmtBarCluster {
public:
  virtual ~TShipyardCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void SetMoveAmount(short amount) override;
  TShipOrder* selectedMetricOrder;
  short selectedMetricValue;
  short selectedMetricStep;

  TShipyardCluster();
  DECLARE_DYNCREATE(TShipyardCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TShipyardCluster, 0x90);
