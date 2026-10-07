#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dfb8
class TIdleMeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TIdleMeAnimation)
  // FUNCTION: IMPERIALISM 0x004ac980
  virtual ~TIdleMeAnimation() override {}
  virtual void Tick() override;

  // NOOP: verified empty in original 0x004ac922
  TIdleMeAnimation() {}

  void IIdleMeAnimation(TView* ownerView);
  void Die();
};

ASSERT_SIZE(TIdleMeAnimation, 0x2c);
