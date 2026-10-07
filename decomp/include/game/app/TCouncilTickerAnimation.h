#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"
#include "game/mfc.h"

class TCouncilView;

// VTABLE: IMPERIALISM 0x0064c410
class TCouncilTickerAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TCouncilTickerAnimation)
  // FUNCTION: IMPERIALISM 0x0049ff50
  virtual ~TCouncilTickerAnimation() override {}
  virtual void Tick() override;

  void InitializeCouncilTicker(TCouncilView* hostPanel, int tickInterval);

  // NOOP: verified empty in original 0x0049fef2
  TCouncilTickerAnimation() {}
};
ASSERT_SIZE(TCouncilTickerAnimation, 0x2c);
