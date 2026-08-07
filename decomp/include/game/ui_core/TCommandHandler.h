#pragma once

#include "compat.h"

#include "game/ui_core/TEventHandler.h"
#include "game/mfc.h"

class TCommand;

// VTABLE: IMPERIALISM 0x00648b20
class TCommandHandler : public TEventHandler {
public:
  DECLARE_DYNCREATE(TCommandHandler)
  // FUNCTION: IMPERIALISM 0x00486610
  virtual ~TCommandHandler() override {}          // slot 0x01 (scalar deleting destructor)
  virtual void PerformCommand(TCommand* command); // slot 0x25 0x486650

  TCommandHandler() : TEventHandler() {}
};
ASSERT_SIZE(TCommandHandler, 0x20);
