#pragma once

#include "compat.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TAnimation;
class TList;
class TMapUberPicture;
class TStream;
struct TQuickDrawSurfaceContext;

// The UI animator: a MacApp-style idle cohandler (g_pUiAnimator, uninstalled from
// g_pGlobalUiRootController via InstallCohandler(this, 0) in Free) that owns the
// transient-animation registry -- a TList of TAnimation-shaped objects keyed by
// their +0x18 registry tag -- plus the shared offscreen surface the animations
// blit into. field10 (the inherited TEventHandler idle-frequency slot) is set by
// InitializeUiTransientObjectRegistry and serialized in WriteTo/ReadFrom.
// Base edge (TEventHandler) recovered from RTTI CRuntimeClass chain:
// TAnimator -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c4e8
class TAnimator : public TEventHandler {
public:
  DECLARE_DYNCREATE(TAnimator)
  virtual ~TAnimator() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a0e50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a0e10
  virtual void Free() override;                    // slot 0x07 0x4a0dc0
  // slot 0x08 ShallowClone inherited unchanged (0x48a7c0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IsEnabled inherited unchanged (0x48a240)
  // slot 0x0b SetEnable inherited unchanged (0x48a260)
  // slot 0x0c GetNextHandler inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f DoEvent inherited unchanged (0x48a280)
  // slot 0x10 HandleEvent inherited unchanged (0x48a2e0)
  // slot 0x11 DoMenuCommand inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  virtual char DoIdle(int action) override; // slot 0x13 0x4a0c30
  // slot 0x14 GetIdleFreq inherited unchanged (0x415d50)
  // slot 0x15 SetIdleFreq inherited unchanged (0x415d70)
  // slot 0x16 GetWindow inherited unchanged (0x48a730)
  // slot 0x17 WantsToBeTarget inherited unchanged (0x48a530)
  // slot 0x18 WillingToResignTarget inherited unchanged (0x48a550)
  // slot 0x19 ResignedTarget inherited unchanged (0x48a690)
  // slot 0x1a TargetValidationFailed inherited unchanged (0x48a6b0)
  // slot 0x1b TargetValidationSucceeded inherited unchanged (0x48a650)
  // slot 0x1c BecameWindowTarget inherited unchanged (0x48a6d0)
  // slot 0x1d ResignedWindowTarget inherited unchanged (0x48a670)
  // slot 0x1e BecameTarget inherited unchanged (0x48a6f0)
  // slot 0x1f BecomeTarget inherited unchanged (0x48a570)
  // slot 0x20 ResignTarget inherited unchanged (0x48a5e0)
  // slot 0x21 SelectOwner inherited unchanged (0x48a710)
  // slot 0x22 IsTarget inherited unchanged (0x48a500)
  // slot 0x23 RemoveBehavior inherited unchanged (0x48a4a0)
  // slot 0x24 AddBehavior inherited unchanged (0x48a4d0)
  virtual undefined OrphanCallChain_C2_I13_004a0c00(); // slot 0x25 0x4a0c00
  void RemoveUiTransientRegistryObjectByTag(int tag);
  // Creates the shared offscreen surface (bounds from the global surface dims, bit
  // depth 8) and the registry TList, and stores the idle frequency into the
  // inherited field10 slot. 0x4a0b20.
  void InitializeUiTransientObjectRegistry(int idleFrequency);
  // Appends an animation object to the registry list. The registry stores
  // heterogeneous animation-shaped objects (tag at +0x18, Free at vtable slot 7);
  // TAnimation* keeps the common call sites cast-free. 0x4a0d10.
  void AddObjectToUiTransientRegistry(TAnimation* animationObject);
  // Walks the registry for the animation whose registryTag18 matches `tag`;
  // null if the animator is null, the list is empty, or nothing matches. 0x4a0d30.
  TAnimation* FindRegisteredAnimationByTag(int tag);
  // Releases every payload owned by registryList24 while retaining the list itself.
  // Null-receiver-safe because retail callers dispatch through g_pUiAnimator directly.
  void FreeUiTransientRegistryPayloads(); // 0x4a0f80
  // Offsets every registered animation's screenRect1C by (dx, dy), then removes and
  // frees any entry whose translated rect no longer intersects clipRect (RECT passed
  // by value: 4 stack dwords). Null-receiver-safe like FindRegisteredAnimationByTag.
  // Called on viewport scrolls (0x51adf0). 0x4a0e90.
  void TranslateListRectsAndDropNonIntersectingEntries(int dx, int dy, RECT clipRect);

  // Object size 0x30 (base TEventHandler ends at 0x20). +0x20 is the offscreen
  // surface the focus animations blit into (read as `*(g_pUiAnimator) + 0x20` at
  // 0x4a0810 and 0x4a05c0). field28 is not touched by the ctor (only zeroed in
  // InitializeUiTransientObjectRegistry); its reader is not yet identified.
  TQuickDrawSurfaceContext* renderSurfaceContext; // +0x20
  TList* registryList24;                          // +0x24 transient-animation registry
  int field28;                                    // +0x28
  TMapUberPicture* mapUberPicture2c;              // +0x2c active strategic-map root

  TAnimator();
};

ASSERT_SIZE(TAnimator, 0x30);
