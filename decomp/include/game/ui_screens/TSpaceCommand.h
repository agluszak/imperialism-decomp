#pragma once

#include "compat.h"

#include "game/ui_core/TCommand.h"
#include "game/mfc.h"

class TSetupRandomMapPicture;

// VTABLE: IMPERIALISM 0x00661b10
class TSpaceCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TSpaceCommand)
  virtual ~TSpaceCommand() override;
  virtual void DoIt() override;
  TSetupRandomMapPicture* setupPicture;
  unsigned char mode;
  unsigned char pad1d[3];

  // NOOP: verified empty in original 0x005751b3
  TSpaceCommand() {}
};
ASSERT_SIZE(TSpaceCommand, 0x20);
