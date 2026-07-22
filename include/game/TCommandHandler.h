#pragma once

#include "game/TEventHandler.h"
#include "game/mfc.h"

class TCommand;

// VTABLE: IMPERIALISM 0x00648b20
class TCommandHandler : public TEventHandler {
public:
  DECLARE_DYNCREATE(TCommandHandler)
  virtual ~TCommandHandler() override;            // slot 0x01 (scalar deleting destructor)
  virtual void PerformCommand(TCommand* command); // slot 0x25 0x486650

  TCommandHandler();
};
