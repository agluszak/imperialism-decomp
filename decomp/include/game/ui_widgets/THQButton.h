#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x666fe0
class THQButton : public TPicture {
public:
  DECLARE_DYNCREATE(THQButton)
  virtual ~THQButton() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void HiliteState(unsigned char enabledState, bool refreshNow) override;
  virtual void SetState(bool value, bool refreshNow);
  virtual void SetMode(short selectionState);
  short normalBitmapId;
  short highlightedBitmapId;
  short selectedBitmapId;
  short unavailableBitmapId;
  short selectionState;
  char padding9A[2];

  THQButton();
};
ASSERT_SIZE(THQButton, 0x9c);
