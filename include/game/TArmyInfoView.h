#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPictureResourceEntryBase {
public:
  TArmyInfoView();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TArmyInfoView is compiler-generated (implicit virtual dtor).
  bool IsSelected(short value = -1, bool refreshNow = true) override;
};

ASSERT_SIZE(TArmyInfoView, 0x90);
