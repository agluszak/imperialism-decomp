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
  virtual ~TCommandHandler() override {}
  virtual void PerformCommand(TCommand* command);

  TCommandHandler() {}
};
ASSERT_SIZE(TCommandHandler, 0x20);
