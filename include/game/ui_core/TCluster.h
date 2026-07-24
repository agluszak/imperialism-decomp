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

  // Frame this cluster into `parent`: adopt the parent's host window, blank the control
  // tag, mark it enabled/visible, record the parent link, copy the offset and size point
  // pairs into the frame fields, register as a child of the parent, and clear the
  // resource context. 0x004915d0, __thiscall.
  void InitializeClusterFrameAndAttachToParent(TView* parent, POINT* offset, POINT* size);
};
