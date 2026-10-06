#pragma once

#include "compat.h"
#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652210
class TPurchaseCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TPurchaseCluster)
  virtual ~TPurchaseCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004cc490
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x4cc470
  // Adopts the 'valu' amount control and pushes its current value into it.
  virtual void StuffValues(TEventHandler* control);     // slot 0x73 0x4cc440
  virtual void SetValue(short nValue, bool redrawFlag); // slot 0x74 0x4cc550
  virtual int GetValue();                               // slot 0x75 0x4cc640
  class TEventHandler* linkedControl;

  TPurchaseCluster();
};

ASSERT_SIZE(TPurchaseCluster, 0x8c);
