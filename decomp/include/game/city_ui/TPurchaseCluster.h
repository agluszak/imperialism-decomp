#pragma once

#include "compat.h"
#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652210
class TPurchaseCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TPurchaseCluster)
  virtual ~TPurchaseCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  // Adopts the 'valu' amount control and pushes its current value into it.
  virtual void StuffValues(TEventHandler* control);
  virtual void SetValue(short nValue, bool redrawFlag);
  virtual int GetValue();
  class TEventHandler* linkedControl;

  TPurchaseCluster();
};

ASSERT_SIZE(TPurchaseCluster, 0x8c);
