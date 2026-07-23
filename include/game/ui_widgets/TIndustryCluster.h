#pragma once

#include "compat.h"
#include "game/ui_widgets/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TProductionOrder;

// VTABLE: IMPERIALISM 0x665ed0
class TIndustryCluster : public TAmtBarCluster {
public:
  virtual ~TIndustryCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00588ff0
  void SetMoveAmount(short amount) override;    // slot 0x74 0x588c30
  virtual void SetMoveAmount(short amount,
                             unsigned char updateControls); // slot 0x75 0x588c60
  virtual void UpdateMax();                                 // slot 0x76 0x588f60
  TProductionOrder* selectedMetricOrder;                    // 0x88
  short selectedMetricValue;                                // 0x8c
  short selectedMetricStep;                                 // 0x8e

  TIndustryCluster();
  DECLARE_DYNCREATE(TIndustryCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TIndustryCluster, 0x90);
