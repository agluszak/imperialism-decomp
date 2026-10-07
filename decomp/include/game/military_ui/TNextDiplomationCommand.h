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

  virtual ~TNextDiplomationCommand() override;
};

ASSERT_SIZE(TNextDiplomationCommand, 0x18);
