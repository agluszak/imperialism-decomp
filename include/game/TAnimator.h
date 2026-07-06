#pragma once

#include "game/TEventHandler.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
struct TQuickDrawSurfaceContext;

// TODO(manifest): describe TAnimator and its role. Base edge (TEventHandler) recovered from RTTI
// CRuntimeClass chain: TAnimator -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c4e8
class TAnimator : public TEventHandler {
public:
  // === BEGIN GENERATED DECLS (TAnimator) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TAnimator)
  virtual ~TAnimator(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a0e50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a0e10
  virtual void Free() override;                    // slot 0x07 0x4a0dc0
  // slot 0x08 ShallowClone inherited unchanged (0x48a7c0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f HandleEvent inherited unchanged (0x48a280)
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x4a0c30
  // slot 0x14 GetCityDialogValueDword10 inherited unchanged (0x415d50)
  // slot 0x15 SetCityDialogValueDword10 inherited unchanged (0x415d70)
  // slot 0x16 OwnerPanel inherited unchanged (0x48a730)
  // slot 0x17 vmethod_0023 inherited unchanged (0x48a530)
  // slot 0x18 vmethod_0024 inherited unchanged (0x48a550)
  // slot 0x19 vmethod_0025 inherited unchanged (0x48a690)
  // slot 0x1a vmethod_0026 inherited unchanged (0x48a6b0)
  // slot 0x1b HandleCityProductionNoOp inherited unchanged (0x48a650)
  // slot 0x1c DispatchUiCommand19ToParent inherited unchanged (0x48a6d0)
  // slot 0x1d DispatchCityProductionAction1A inherited unchanged (0x48a670)
  // slot 0x1e DispatchCityProductionAction1B inherited unchanged (0x48a6f0)
  // slot 0x1f ActivateCityProductionViewIfAllowed inherited unchanged (0x48a570)
  // slot 0x20 vmethod_0080 inherited unchanged (0x48a5e0)
  // slot 0x21 vmethod_0081 inherited unchanged (0x48a710)
  // slot 0x22 vmethod_0032 inherited unchanged (0x48a500)
  // slot 0x23 vmethod_0033 inherited unchanged (0x48a4a0)
  // slot 0x24 SetUiResourceOwner inherited unchanged (0x48a4d0)
  virtual undefined OrphanCallChain_C2_I13_004a0c00(); // slot 0x25 0x4a0c00
                                                       // === END GENERATED DECLS (TAnimator) ===
  void RemoveUiTransientRegistryObjectByTag(int tag);

  // Object size 0x30 (base TEventHandler ends at 0x20). +0x20 is the offscreen
  // surface the focus animations blit into (read as `*(g_pUiAnimator) + 0x20` at
  // 0x4a0810 and 0x4a05c0); the remaining three dwords are not yet recovered.
  TQuickDrawSurfaceContext* renderSurfaceContext; // +0x20
  int field24;                                    // +0x24
  int field28;                                    // +0x28
  int field2c;                                    // +0x2c

  TAnimator();
};

