#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65efd8
class TToggleButton : public TPicture {
public:
  virtual ~TToggleButton() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual bool IsSelected(); // slot 0x73 0x571330 (forwarder to the bool IsActionable slot)
  virtual void Select(bool isPressed, bool notifyParent);
  TToggleButton();
  DECLARE_DYNCREATE(TToggleButton)
};

ASSERT_SIZE(TToggleButton, 0x90);
