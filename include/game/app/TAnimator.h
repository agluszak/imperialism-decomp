#pragma once

#include "compat.h"
#include "game/ui_core/TEventHandler.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TAnimation;
class TList;
class TMapUberPicture;
class TStream;
struct TQuickDrawSurfaceContext;

// The UI animator: a MacApp-style idle cohandler (g_pUiAnimator, uninstalled from
// g_pAmbitApplication via InstallCohandler(this, 0) in Free) that owns the
// transient-animation registry -- a TList of TAnimation-shaped objects keyed by
// their +0x18 registry tag -- plus the shared offscreen surface the animations
// blit into. idleFrequencyTicks (inherited from TEventHandler) is set by
// IAnimator and serialized in WriteTo/ReadFrom.
// Base edge (TEventHandler) recovered from RTTI CRuntimeClass chain:
// TAnimator -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c4e8
class TAnimator : public TEventHandler {
public:
  DECLARE_DYNCREATE(TAnimator)
  virtual ~TAnimator() override;                   // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a0e50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a0e10
  virtual void Free() override;                    // slot 0x07 0x4a0dc0
  virtual char DoIdle(int action) override;        // slot 0x13 0x4a0c30
  // Mac CodeWarrior identity: TAnimator::Install(). Counterpart of Free's
  // InstallCohandler(this, 0).
  virtual void Install(); // slot 0x25 0x4a0c00
  void RemoveUiTransientRegistryObjectByTag(int tag);
  // Creates the shared offscreen surface (bounds from the global surface dims, bit
  // depth 8) and the registry TList, and stores the idle frequency into the
  // inherited idle-frequency slot. 0x4a0b20.
  void IAnimator(int idleFrequency);
  // Appends an animation object to the registry list. The registry stores
  // heterogeneous animation-shaped objects (tag at +0x18, Free at vtable slot 7);
  // TAnimation* keeps the common call sites cast-free. 0x4a0d10.
  void AddObjectToUiTransientRegistry(TAnimation* animationObject);
  // Walks the registry for the animation whose registryTag matches `tag`;
  // null if the animator is null, the list is empty, or nothing matches. 0x4a0d30.
  TAnimation* FindRegisteredAnimationByTag(int tag);
  // Releases every payload owned by registryList24 while retaining the list itself.
  // Null-receiver-safe because retail callers dispatch through g_pUiAnimator directly.
  void FreeUiTransientRegistryPayloads(); // 0x4a0f80
  // Offsets every registered animation's screenRect by (dx, dy), then removes and
  // frees any entry whose translated rect no longer intersects clipRect (RECT passed
  // by value: 4 stack dwords). Null-receiver-safe like FindRegisteredAnimationByTag.
  // Called on viewport scrolls (0x51adf0). 0x4a0e90.
  void TranslateListRectsAndDropNonIntersectingEntries(int dx, int dy, RECT clipRect);

  // Object size 0x30 (base TEventHandler ends at 0x20). +0x20 is the offscreen
  // surface the focus animations blit into (read as `*(g_pUiAnimator) + 0x20` at
  // 0x4a0810 and 0x4a05c0). field28 is not touched by the ctor (only zeroed in
  // IAnimator); its reader is not yet identified.
  TQuickDrawSurfaceContext* renderSurfaceContext; // +0x20
  TList* registryList24;                          // +0x24 transient-animation registry
  int field28;                                    // +0x28
  TMapUberPicture* mapUberPicture2c;              // +0x2c active strategic-map root

  TAnimator();
};

ASSERT_SIZE(TAnimator, 0x30);
