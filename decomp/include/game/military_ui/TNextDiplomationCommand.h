#pragma once

#include "game/ui_core/TCommand.h"
#include "game/ui_tags_military.h"

// VTABLE: IMPERIALISM 0x00654e50
class TNextDiplomationCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNextDiplomationCommand)
  void DoIt() override;

  TNextDiplomationCommand() : TCommand() {}

  void PostThyself();

  virtual ~TNextDiplomationCommand() override; // slot 0x01 scalar deleting dtor 0x4f0dd0
};

ASSERT_SIZE(TNextDiplomationCommand, 0x18);
