#pragma once

#include "game/app/TAnimation.h"

class TView;

// VTABLE: IMPERIALISM 0x0064c3d0
class TOneTimeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TOneTimeAnimation)
  // FUNCTION: IMPERIALISM 0x0049fd20
  virtual ~TOneTimeAnimation() override {}

  virtual void Tick() override;

  bool completeFlag; // set once all frames have played (stops the modal pump)

  void InitializeOneTimeAnimation(TView* view, RECT* rect, short frameCountArg, short effectId,
                                  int tickLimit, int registryTag);
};

ASSERT_SIZE(TOneTimeAnimation, 0x30);
