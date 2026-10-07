#pragma once

#include "compat.h"
#include "game/ui_widgets/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TProductionOrder;

// VTABLE: IMPERIALISM 0x666318
class TRailCluster : public TAmtBarCluster {
public:
  virtual ~TRailCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetMoveAmount(short dragValue, bool updateFlag);
  void SetMoveAmount(short amount) override;
  virtual void UpdateMax();
  TProductionOrder* selectedMetricOrder;
  short selectedMetricValue;
  short selectedMetricStep;

  TRailCluster();
  DECLARE_DYNCREATE(TRailCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TRailCluster, 0x90);
