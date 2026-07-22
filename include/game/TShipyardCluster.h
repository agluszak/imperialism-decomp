#pragma once

#include "compat.h"
#include "game/TAmtBarCluster.h"

struct CRuntimeClass;
class TAmtBar;
class TShipOrder;

// VTABLE: IMPERIALISM 0x666760
class TShipyardCluster : public TAmtBarCluster {
public:
  virtual ~TShipyardCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0058a940
  void SetMoveAmount(short amount) override;    // slot 0x74 0x58a690
  TShipOrder* selectedMetricOrder;           // 0x88
  short selectedMetricValue;                 // 0x8c
  short selectedMetricStep;                  // 0x8e

  TShipyardCluster();
  DECLARE_DYNCREATE(TShipyardCluster)
  void DoPostCreate(int styleSeed) override;
};

ASSERT_SIZE(TShipyardCluster, 0x90);
