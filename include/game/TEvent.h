#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TEventHandler;

// McApp UI command/event base. Layout partially recovered; size 0x14.
// Base recovered from CRuntimeClass descriptor: TEvent -> TObject -> CObject.
class TEvent : public TObject {
public:
  DECLARE_DYNCREATE(TEvent)

  ~TEvent();

  int commandNumber;            // 0x04
  int dispatchMessage;          // 0x08
  TEventHandler* sourceHandler; // 0x0c
  TEventHandler* targetHandler; // 0x10

  TEvent();
};

ASSERT_SIZE(TEvent, 0x14);
