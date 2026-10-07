#pragma once

#include "compat.h"
#include "game/ui_core/TEventHandler.h"
#include "game/mfc.h"

class TAnimation;
class TList;
class TMapUberPicture;
class TStream;
struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x0064c4e8
class TAnimator : public TEventHandler {
public:
  DECLARE_DYNCREATE(TAnimator)
  // FUNCTION: IMPERIALISM 0x004a0b00
  virtual ~TAnimator() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual bool DoIdle(int action) override;
  virtual void Install();
  void FreeAni(int tag);
  void IAnimator(int idleFrequency);
  void AddAnimation(TAnimation* animationObject);
  TAnimation* FindAni(int tag);
  void FreeAllAnis();
  void UpdateAniLocs(int dx, int dy, RECT clipRect);

  TQuickDrawSurfaceContext* renderSurfaceContext;
  TList* registryList; // +0x24 transient-animation registry
  int overlayPhaseTickCount;
  TMapUberPicture* mapUberPicture; // +0x2c active strategic-map root

  TAnimator();
};

ASSERT_SIZE(TAnimator, 0x30);
