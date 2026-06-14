#pragma once

#include "game/TUberCluster.h"

// VTABLE: IMPERIALISM 0x00664d38
struct CRuntimeClass;
class TUnitToolbarCluster : public TUberCluster {
public:
  using TUberCluster::DispatchEvent;

  TUnitToolbarCluster();
  CRuntimeClass* GetRuntimeClass() override;

  virtual void DispatchEvent(int eventClass, void* eventPayload, int eventFlags);

  // We'll declare the static creation methods.
  static TUnitToolbarCluster* CreateInstance();
  void* DestructAndMaybeFree(int freeSelfFlag);

  // Actually, we don't know UpdateTradeResourceSelectionByIndex's slot yet.
  // It takes (int nResourceIndex). Let's just declare it as a normal method for now
  // or a vmethod if we find it in vtable.
  void UpdateTradeResourceSelectionByIndex(int nResourceIndex);
};
