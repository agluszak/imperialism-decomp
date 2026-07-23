#pragma once

#include "compat.h"
#include "game/ui_widgets/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TProductionOrder;

// VTABLE: IMPERIALISM 0x666318
class TRailCluster : public TAmtBarCluster {
public:
  virtual ~TRailCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00589da0
  virtual void SetMoveAmount(short amount,
                             unsigned char updateControls); // slot 0x75 0x5899f0
  void SetMoveAmount(short amount) override;                // slot 0x74 0x5899c0
  virtual void UpdateMax();                                 // slot 0x76 0x589d10
  TProductionOrder* selectedMetricOrder;                    // 0x88
  short selectedMetricValue;                                // 0x8c
  short selectedMetricStep;                                 // 0x8e

  TRailCluster();
  DECLARE_DYNCREATE(TRailCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TRailCluster, 0x90);
