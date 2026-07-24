#pragma once

#include "compat.h"

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

class TSetupRandomMapPicture;

// VTABLE: IMPERIALISM 0x00661b10
class TSpaceCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TSpaceCommand)
  virtual ~TSpaceCommand() override;      // slot 0x01 (scalar deleting destructor)
  virtual void DoIt() override;           // slot 0x0b 0x5751f0
  TSetupRandomMapPicture* setupPicture18; // +0x18
  unsigned char mode1c;                   // +0x1c
  unsigned char pad1d[3];

  TSpaceCommand();
};
ASSERT_SIZE(TSpaceCommand, 0x20);
