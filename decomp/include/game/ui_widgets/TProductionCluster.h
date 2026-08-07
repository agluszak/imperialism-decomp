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
  virtual ~TProductionCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;               // slot 0x0f 0x005869c0
  virtual void SetLaborRate(short laborRate);                 // slot 0x74 0x586a60
  virtual void SetStockpileRate(short stockpileRate);         // slot 0x75 0x586ab0
  virtual void SetStockpiles(short* current, short* maximum); // slot 0x76 0x586a80
  int field88;
  short laborRate8c;
  short stockpileRate8e;
  short* currentStockpile90;
  short* maximumStockpile94;

  TProductionCluster();
  DECLARE_DYNCREATE(TProductionCluster)
};

ASSERT_SIZE(TProductionCluster, 0x98);

void HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(TProductionCluster* cluster,
                                                                        int commandId,
                                                                        void* eventArg,
                                                                        int eventExtra);
