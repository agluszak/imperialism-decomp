#pragma once

#include "compat.h"
#include "game/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPicture {
public:
  virtual ~TArmyInfoView() override; // slot 0x01 (scalar deleting destructor)
  TArmyInfoView();
  DECLARE_DYNCREATE(TArmyInfoView)
  virtual bool IsSelected(short value = -1, bool refreshNow = true);
};

ASSERT_SIZE(TArmyInfoView, 0x90);
