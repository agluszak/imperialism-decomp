#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPictureResourceEntryBase {
public:
  TArmyInfoView();
  virtual ~TArmyInfoView();
};

ASSERT_SIZE(TArmyInfoView, 0x90);
