#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65efd8
class TToggleButton : public TPictureResourceEntryBase {
public:
  TToggleButton();
  CRuntimeClass* GetRuntimeClass() const override;
  // ~TToggleButton is compiler-generated (implicit virtual dtor).

  bool IsSelected(short value = -1, bool refreshNow = true) override; // slot 0x1cc
  virtual void Select(bool isPressed, bool notifyParent);             // slot 0x1d0

  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override; // slot 0x3c 0x571170
  char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                     int arg4) override; // slot 0x118 0x5712a0
};

ASSERT_SIZE(TToggleButton, 0x90);
