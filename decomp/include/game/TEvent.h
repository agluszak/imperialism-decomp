#pragma once

#include "compat.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

class TEventHandler;

// VTABLE: IMPERIALISM 0x00649770
class TEvent : public TObject {
public:
  DECLARE_DYNCREATE(TEvent)

  // FUNCTION: IMPERIALISM 0x00492ca0
  ~TEvent() override {}

  int commandNumber;
  int dispatchMessage;
  TEventHandler* sourceHandler;
  TEventHandler* targetHandler;

  TEvent() : commandNumber(0), dispatchMessage(0), sourceHandler(0), targetHandler(0) {}
};

ASSERT_SIZE(TEvent, 0x14);
