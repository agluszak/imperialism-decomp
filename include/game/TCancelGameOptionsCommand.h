#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065bff0
class TCancelGameOptionsCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TCancelGameOptionsCommand)
  virtual ~TCancelGameOptionsCommand() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;                  // slot 0x0b 0x542520

  // Fully inlined at every construction site (base TCommand ctor call + vtable
  // store); defined in-class so `new TCancelGameOptionsCommand()` reproduces that shape.
  TCancelGameOptionsCommand() : TCommand() {}
};
