#pragma once

#include "game/ui_core/TControl.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  DECLARE_DYNCREATE(TCluster)
  virtual ~TCluster() override;             // slot 0x01 (scalar deleting destructor)
  virtual TObject* ShallowClone() override; // slot 0x08 0x4918a0
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;             // slot 0x0f 0x00491650
  virtual int GetSelectedChildTag();                        // slot 0x71 0x491770
  virtual void SetSelectedChildTagAndRefresh(int childTag); // slot 0x72 0x491790 (1 arg; RET 4)
  int selectedChildTag;

  TCluster();
};
