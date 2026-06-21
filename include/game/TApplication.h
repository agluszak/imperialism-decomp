#pragma once

#include "decomp_types.h"
#include "game/ApplicationUiRootEmbeddedList.h"
#include "game/TEventHandler.h"

class TView;

// Application UI root controller — global modal-view gatekeeper installed at startup.
// Inherits the shared 37-slot base interface (indices 0x00-0x24) and fields through +0x1c
// from TEventHandler (the same base TView derives from). Introduces its own slots 0x25-0x2a
// (byte offsets 0x94-0xa8): a command-handler dispatch, the active-view get/set pair, a
// viewport-edge auto-scroll no-op, an intrusive-list insert/remove, and a per-entry tick
// walk over the embedded list at +0x2c (secondary vtable 0x00648ca8). Size 0x48.
// VTABLE: IMPERIALISM 0x00648bd8
class TApplication : public TEventHandler {
public:
// === BEGIN GENERATED DECLS (TApplication) — refreshed by recover-class; do not hand-edit ===
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48a1b0)
  // slot 0x08 ShallowClone inherited unchanged (0x48a7c0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  virtual void vmethod_0013(int* cmd) override; // slot 0x0d 0x486b50
  // slot 0x0e vmethod_0014 inherited unchanged (0x48a3f0)
  // slot 0x0f HandleEvent inherited unchanged (0x48a280)
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
  virtual void vmethod_0017(int param) override; // slot 0x11 0x486ba0
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  // slot 0x13 CanHandleCityDialogActionFalse inherited unchanged (0x48a480)
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
  // slot 0x25 ConstructTCommandHandlerBaseState inherited unchanged (0x486650)
  virtual undefined OrphanTiny_SetDwordEcxOffset_20_00486880(undefined4 param_1) override; // slot 0x26 0x486880
  virtual undefined OrphanTiny_GetDwordEcxOffset_20_004868a0() override; // slot 0x27 0x4868a0
  // slot 0x34 GetRuntimeClass inherited unchanged (0x606fba)
  virtual undefined WrapperFor_FreeHeapBufferIfNotNull_At00486f60(byte param_1) override; // slot 0x35 0x486f60
  virtual undefined SerializeRecordList_0x0C_WithBlockPool_B() override; // slot 0x36 0x486df0
  // slot 0x37 AssertValid inherited unchanged (0x412bf0)
  // slot 0x38 Dump inherited unchanged (0x412c10)
// === END GENERATED DECLS (TApplication) ===
  TApplication();
  ~TApplication() override;

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  virtual CRuntimeClass* GetRuntimeClass() const override;

  // vtable index 0x25 (0x00486650): dispatch the queued command-handler argument by
  // calling its vtable slot 0x0b then its slot 0x07 (release/destroy). DEFERRED: the
  // argument's real type is a TCommandHandler descendant (not yet recovered as a class),
  // and its slot 0x0b is a no-arg command-processing method distinct from TEventHandler's
  // slot-0x0b SetControlValue(int). Porting this correctly needs TCommandHandler recovery
  // first; kept as a placeholder so the vtable layout stays correct.
  virtual void vmethod_0037();
  // vtable index 0x26 (0x00486880): store the active modal view pointer.
  virtual void SetActiveView(TView* view);
  // vtable index 0x27 (0x004868a0): load the active modal view pointer.
  virtual TView* GetActiveView();
  // vtable index 0x28 (0x00486990): viewport-edge auto-scroll hook; no-op in the original
  // (RET 0xc — takes 3 stack args). Kept as a real virtual so descendants can override.
  virtual void HandleTurnEventViewportEdgeAutoScroll(int arg1, int arg2, int arg3);
  // vtable index 0x29 (0x004869b0): when insertFlag is nonzero, allocate (or reuse from
  // the free list) a 12-byte node, store `value` at node+8, and link it at the list head;
  // when zero, find the first node whose node+8 equals `value`, unlink it, and return the
  // node to the free list (freeing the block chain when the list becomes empty).
  virtual void InsertOrRemoveTrackedEntry(int value, char insertFlag);
  // vtable index 0x2a (0x00486b10): walk the embedded list and invoke each entry's tick
  // method (slot at node+8 receiver, passing arg) via the per-entry thunk.
  virtual void TickEachTrackedEntry(int arg);

  TView* activeView;                          // 0x20
  int screenModeAt24;                         // 0x24
  int field28;                                // 0x28
  ApplicationUiRootEmbeddedList embeddedList; // 0x2c
};

extern TApplication* g_pApplicationUiRootController;

// === BEGIN GENERATED (TApplication) — refreshed by `just gen-class TApplication`; do not hand-edit ===
// clang-format off
// vtable @ 0x00648bd8 (57 slots), object size 0x48, base TCommandHandler
//   slot 0x00  byte 0x00  0x00486740  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x004867b0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0048a1b0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x08  byte 0x20  0x0048a7c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x00486b50  override  VTableSlot0D
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0048a280  inherited OrphanRetStub_0059add0
//   slot 0x10  byte 0x40  0x0048a2e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x00486ba0  override  DispatchReflectedControlMessageOrFallback
//   slot 0x12  byte 0x48  0x0048a380  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x0048a480  inherited VTableSlot13
//   slot 0x14  byte 0x50  0x00415d50  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x00415d70  inherited VTableSlot15
//   slot 0x16  byte 0x58  0x0048a730  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x17  byte 0x5c  0x0048a530  inherited VTableSlot17
//   slot 0x18  byte 0x60  0x0048a550  inherited SetForeignMinisterReadyFlag14
//   slot 0x19  byte 0x64  0x0048a690  inherited VTableSlot19
//   slot 0x1a  byte 0x68  0x0048a6b0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1b  byte 0x6c  0x0048a650  inherited VTableSlot1B
//   slot 0x1c  byte 0x70  0x0048a6d0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1d  byte 0x74  0x0048a670  inherited VTableSlot1D
//   slot 0x1e  byte 0x78  0x0048a6f0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1f  byte 0x7c  0x0048a570  inherited VTableSlot1F
//   slot 0x20  byte 0x80  0x0048a5e0  inherited GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x0048a710  inherited VTableSlot21
//   slot 0x22  byte 0x88  0x0048a500  inherited GetTEventHandlerClassNamePointer
//   slot 0x23  byte 0x8c  0x0048a4a0  inherited VTableSlot23
//   slot 0x24  byte 0x90  0x0048a4d0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x25  byte 0x94  0x00486650  inherited ConstructTCommandHandlerBaseState
//   slot 0x26  byte 0x98  0x00486880  override  OrphanTiny_SetDwordEcxOffset_20_00486880
//   slot 0x27  byte 0x9c  0x004868a0  override  OrphanTiny_GetDwordEcxOffset_20_004868a0
//   slot 0x28  byte 0xa0  0x00486990  override  DispatchVirtualSlotF8_WithArg
//   slot 0x29  byte 0xa4  0x004869b0  override  Helper_Uses_AllocateAndLinkBlockHead_At004869b0
//   slot 0x2a  byte 0xa8  0x00486b10  override  OnEndPrintPreview
//   slot 0x2b  byte 0xac  0x00000000  null      (null)
//   slot 0x2c  byte 0xb0  0x00000000  null      (null)
//   slot 0x2d  byte 0xb4  0x00000000  null      (null)
//   slot 0x2e  byte 0xb8  0x00000000  null      (null)
//   slot 0x2f  byte 0xbc  0x00000000  null      (null)
//   slot 0x30  byte 0xc0  0x00000000  null      (null)
//   slot 0x31  byte 0xc4  0x00000000  null      (null)
//   slot 0x32  byte 0xc8  0x00000000  null      (null)
//   slot 0x33  byte 0xcc  0x00000000  null      (null)
//   slot 0x34  byte 0xd0  0x00606fba  override  GetRuntimeClass
//   slot 0x35  byte 0xd4  0x00486f60  override  WrapperFor_FreeHeapBufferIfNotNull_At00486f60
//   slot 0x36  byte 0xd8  0x00486df0  override  SerializeRecordList_0x0C_WithBlockPool_B
//   slot 0x37  byte 0xdc  0x00412bf0  override  AssertValid
//   slot 0x38  byte 0xe0  0x00412c10  override  Dump
// object size 0x48 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TApplication) ===
