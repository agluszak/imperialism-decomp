#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPicture {
public:
  virtual ~TArmyInfoView() override;
  TArmyInfoView();
  DECLARE_DYNCREATE(TArmyInfoView)
  virtual void StuffValues(short cityRecordIndex, int* categoryCounts);
};

ASSERT_SIZE(TArmyInfoView, 0x90);
