#pragma once

#include "compat.h"
#include "game/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dfb8
class TIdleMeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TIdleMeAnimation)
  virtual ~TIdleMeAnimation() override; // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;         // slot 0x0a 0x4aca60
  // RTTI oracle: sizeof(TIdleMeAnimation) == 0x2c, identical to TAnimation -- no own
  // fields.

  TIdleMeAnimation() {}

  // Post-construction init (0x4ac9c0): stamps the animation with the next value of
  // the g_nIdleMeAnimationNextRegistryTag counter (as its registryTag18), zeroes the
  // rect/frame state via the base helper, and registers itself with g_pUiAnimator.
  void InitializeIdleAnimation(TView* ownerView);
};

ASSERT_SIZE(TIdleMeAnimation, 0x2c);
