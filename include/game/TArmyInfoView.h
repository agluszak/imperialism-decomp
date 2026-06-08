#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPictureResourceEntryBase {
public:
  TArmyInfoView();
  // ~TArmyInfoView is compiler-generated (implicit virtual dtor).
};

ASSERT_SIZE(TArmyInfoView, 0x90);
