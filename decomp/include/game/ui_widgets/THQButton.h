#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x666fe0
class THQButton : public TPicture {
public:
  DECLARE_DYNCREATE(THQButton)
  virtual ~THQButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0058b7f0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x58b6e0
  virtual void HiliteState(unsigned char enabledState,
                           bool refreshNow) override;                   // slot 0x70 0x58b750
  virtual void SetState(bool value, bool refreshNow);                   // slot 0x73 0x58b890
  virtual void SetMode(short selectionState); // slot 0x74 0x58b8d0
  short normalBitmapId;
  short highlightedBitmapId;
  short selectedBitmapId;
  short unavailableBitmapId;
  short selectionState;
  char padding9A[2];

  THQButton();
};
ASSERT_SIZE(THQButton, 0x9c);
