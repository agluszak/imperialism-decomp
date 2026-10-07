#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645888
class TTacticalHolaPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTacticalHolaPicture)
  virtual ~TTacticalHolaPicture() override;

  TTacticalHolaPicture();

  void StuffValues(int nationA, int nationB, int nationAIsLocalSide, int battleSiteIndex);
};
ASSERT_SIZE(TTacticalHolaPicture, 0x90);
