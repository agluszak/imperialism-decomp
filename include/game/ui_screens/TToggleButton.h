#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65efd8
class TToggleButton : public TPicture {
public:
  virtual ~TToggleButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571170
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin) override; // slot 0x46 0x5712a0
  virtual bool IsSelected(); // slot 0x73 0x571330 (forwarder to the bool IsActionable slot)
  virtual void Select(bool isPressed, bool notifyParent); // slot 0x74 0x571350
  TToggleButton();
  DECLARE_DYNCREATE(TToggleButton)
};

ASSERT_SIZE(TToggleButton, 0x90);
