#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"
#include "game/mfc.h"

class TCouncilView;

// VTABLE: IMPERIALISM 0x0064c410
class TCouncilTickerAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TCouncilTickerAnimation)
  virtual ~TCouncilTickerAnimation() override; // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;                // slot 0x0a 0x49ffe0

  // Initializes the inherited TAnimation fields directly (inline duplicate of
  // TAnimation::InitializeAnimation's pattern, not a call to it): owner view,
  // zeroed frame/tag state, the tick interval, and a zeroed screen rect.
  void InitializeCouncilTicker(TCouncilView* hostPanel, int tickInterval);

  TCouncilTickerAnimation();
};
ASSERT_SIZE(TCouncilTickerAnimation, 0x2c);
