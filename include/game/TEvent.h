#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TEventHandler;

// McApp UI command/event base. Layout partially recovered; size 0x14.
// Base recovered from CRuntimeClass descriptor: TEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00649770
class TEvent : public TObject {
public:
  DECLARE_DYNCREATE(TEvent)

  ~TEvent() override;

  int commandNumber;            // 0x04
  int dispatchMessage;          // 0x08
  TEventHandler* sourceHandler; // 0x0c
  TEventHandler* targetHandler; // 0x10

  // Defined inline: every original `new TEvent()` site (CreateObject 0x489f00, the
  // TWorldView overlay dispatchers 0x5963d0/0x596440) inlines the ctor -- no ctor
  // call and no EH frame -- so the definition must be visible for MSVC5 to inline it.
  TEvent() : commandNumber(0), dispatchMessage(0), sourceHandler(0), targetHandler(0) {}
};

ASSERT_SIZE(TEvent, 0x14);
