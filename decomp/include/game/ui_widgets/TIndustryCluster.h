#pragma once

#include "compat.h"
#include "game/ui_widgets/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TProductionOrder;

// VTABLE: IMPERIALISM 0x665ed0
class TIndustryCluster : public TAmtBarCluster {
public:
  virtual ~TIndustryCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void SetMoveAmount(short amount) override;
  virtual void SetMoveAmount(short amount, bool updateControls);
  virtual void UpdateMax();
  TProductionOrder* selectedMetricOrder;
  short selectedMetricValue;
  short selectedMetricStep;

  TIndustryCluster();
  DECLARE_DYNCREATE(TIndustryCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TIndustryCluster, 0x90);
