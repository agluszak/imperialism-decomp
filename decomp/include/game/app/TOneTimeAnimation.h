#pragma once

#include "game/app/TAnimation.h"

class TView;

// VTABLE: IMPERIALISM 0x0064c3d0
class TOneTimeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TOneTimeAnimation)
  // FUNCTION: IMPERIALISM 0x0049fd20
  virtual ~TOneTimeAnimation() override {} // slot 0x01 (scalar deleting destructor); dtor 0x49fd20

  virtual void Tick() override; // slot 0x0a 0x49fde0

  bool completeFlag; // 0x2c — set once all frames have played (stops the modal pump)
  char pad2d[3];

  void InitializeOneTimeAnimation(TView* view, RECT* rect, short frameCountArg, short effectId,
                                  int tickLimit, int registryTag);
};

ASSERT_SIZE(TOneTimeAnimation, 0x30);
