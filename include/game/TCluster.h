#pragma once

#include "game/TControl.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  int field84;

  TCluster();

  CRuntimeClass* GetRuntimeClass() const override;        // 0x00
  TObject* ShallowClone() override; // 0x20
  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override; // 0x3c

  // Slots 0x1C4 - 0x1C8 (0x71, 0x72)
  virtual int GetField84();
  virtual void SetControlClassAndRefresh(int classState, int refreshFlag);
};
