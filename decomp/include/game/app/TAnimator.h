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
  virtual ~TAnimator() override {}                 // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a0e50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a0e10
  virtual void Free() override;                    // slot 0x07 0x4a0dc0
  virtual bool DoIdle(int action) override;        // slot 0x13 0x4a0c30
  virtual void Install();                          // slot 0x25 0x4a0c00
  void FreeAni(int tag);
  void IAnimator(int idleFrequency);
  void AddAnimation(TAnimation* animationObject);
  TAnimation* FindAni(int tag);
  void FreeAllAnis(); // 0x4a0f80
  void UpdateAniLocs(int dx, int dy, RECT clipRect);

  TQuickDrawSurfaceContext* renderSurfaceContext; // +0x20
  TList* registryList;                            // +0x24 transient-animation registry
  int overlayPhaseTickCount;                      // +0x28
  TMapUberPicture* mapUberPicture;                // +0x2c active strategic-map root

  TAnimator();
};

ASSERT_SIZE(TAnimator, 0x30);
