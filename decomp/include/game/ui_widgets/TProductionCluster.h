#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_screens/TUberCluster.h"

struct CRuntimeClass;
class TEvent;
class TEventHandler;

// VTABLE: IMPERIALISM 0x6653c8
class TProductionCluster : public TUberCluster {
public:
  virtual ~TProductionCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetLaborRate(short laborRate);
  virtual void SetStockpileRate(short stockpileRate);
  virtual void SetStockpiles(short* current, short* maximum);
  int field88;
  short laborRate;
  short stockpileRate;
  short* currentStockpile;
  short* maximumStockpile;

  TProductionCluster();
  DECLARE_DYNCREATE(TProductionCluster)
};

ASSERT_SIZE(TProductionCluster, 0x98);

void HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(TProductionCluster* cluster,
                                                                        int commandId,
                                                                        void* eventArg,
                                                                        int eventExtra);
