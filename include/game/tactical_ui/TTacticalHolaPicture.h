#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645888
class TTacticalHolaPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTacticalHolaPicture)
  virtual ~TTacticalHolaPicture() override; // slot 0x01 (scalar deleting destructor)

  TTacticalHolaPicture();

  // Configures the battle-intro ('hola', dialog 0xf19) coats-of-arms and site labels
  // for the two nations. 0x005ad760, __thiscall, ret 0x10 (renamed off the
  // junk TTask::CreateTTaskInstance attribution).
  void ConfigureBattleIntroCoatsAndSiteLabels(int nationA, int nationB, int nationAIsLocalSide,
                                              int battleSiteIndex);
};
ASSERT_SIZE(TTacticalHolaPicture, 0x90);
