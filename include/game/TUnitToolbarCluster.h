#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00664d38
class TUnitToolbarCluster : public TUberCluster {
public:
  using TUberCluster::DispatchEvent;

  TUnitToolbarCluster();
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual int IsTradeControlAtMinimum() override;
  virtual void UpdateTradeResourceSelectionByIndex(int nResourceIndex);

  static TUnitToolbarCluster* CreateInstance();
};
