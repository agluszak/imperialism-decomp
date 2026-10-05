#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dfb8
class TIdleMeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TIdleMeAnimation)
  // FUNCTION: IMPERIALISM 0x004ac980
  virtual ~TIdleMeAnimation() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;           // slot 0x0a 0x4aca60
  // RTTI oracle: sizeof(TIdleMeAnimation) == 0x2c, identical to TAnimation -- no own
  // fields.

  // NOOP: verified empty in original 0x004ac922 (no standalone TIdleMeAnimation::TIdleMeAnimation body exists: construction is fully inlined into CreateObject 0x004ac920; that address is its operator-new call site)
  TIdleMeAnimation() {}

  void IIdleMeAnimation(TView* ownerView);
  void Die();
};

ASSERT_SIZE(TIdleMeAnimation, 0x2c);
