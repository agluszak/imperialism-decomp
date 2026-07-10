#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TView;
class TPtrList;
struct TQuickDrawSurfaceContext;

// Display-surface / GWorld manager (singleton g_pDisplayMgr @ 0x006a2158).
// VTABLE: IMPERIALISM 0x00656680
class TDisplayMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TDisplayMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TDisplayMgr)
  virtual ~TDisplayMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4fea60
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined InitializeTurnOrderNavigationDialogByViewportSize(); // slot 0x0a 0x4fe840
  virtual void InitializeBitmapSurfaceContextWithRetry(TQuickDrawSurfaceContext** outContext,
                                                       short bitDepth,
                                                       RECT* bounds);    // slot 0x0b 0x4feab0
  virtual void EnsurePrimaryRenderSurfaceContextAllocated();             // slot 0x0c 0x4feb80
  virtual undefined WrapperFor_thunk_NoOpCallback_00498ca0_At004febd0(); // slot 0x0d 0x4febd0
  virtual undefined WrapperFor_thunk_NoOpCallback_00498ca0_At004fed00(); // slot 0x0e 0x4fed00
  virtual undefined OrphanRetStub_004fed50(char param_1);                // slot 0x0f 0x4fed50
  virtual undefined AssertUDisplayMgrLines614And616(char param_1);       // slot 0x10 0x4fed70
  virtual undefined AssertUDisplayMgrLine471();                          // slot 0x11 0x4fec20
  virtual undefined AssertUDisplayMgrLine495();                          // slot 0x12 0x4fec50
  // slot 0x13 0x4fec80 — forwards (message, messageStoreRef) to the TViewMgr
  // RunControlStringProvider dispatch.
  virtual void DispatchDisplayManagerControlStringMessage(CString message,
                                                          CString* messageStoreRef);
  virtual undefined
  LoadMainViewClipSnapshotIntoQuickDrawState(undefined2 param_1);  // slot 0x14 0x4fedc0
  virtual void SetMapTileIconVariantTriplet(undefined1* param_1);  // slot 0x15 0x4fefc0
  virtual undefined DispatchUiWindowStatusTickForClass99Windows(); // slot 0x16 0x4ff000
  // === END GENERATED DECLS (TDisplayMgr) ===

  // Frees the TQuickDrawSurfaceContext record held in `slot` and clears the slot.
  // Real __thiscall on the display manager (every callsite loads ecx = g_pDisplayMgr)
  // even though the body never reads `this`. 0x4feb50, ret 4.
  void FreeQuickDrawSurfaceContextSlot(struct TQuickDrawSurfaceContext** slot);

  TView* activeDialog;      // +0x04
  short viewportMetric;     // +0x08 (default 8)
  short dialogActiveFlag;   // +0x0a
  short field0c;            // +0x0c
  short eventCode0e;        // +0x0e (0x7d1 / 0x7d2)
  unsigned char tileIcon10; // +0x10
  unsigned char tileIcon11; // +0x11
  unsigned char tileIcon12; // +0x12
  unsigned char tileIcon13; // +0x13
  unsigned char tileIcon14; // +0x14
  unsigned char tileIcon15; // +0x15
  unsigned char tileIcon16; // +0x16
  unsigned char tileIcon17; // +0x17
  int field18;              // +0x18
  short clipSnapshotEvent;  // +0x1c
  unsigned short field1e;   // +0x1e
  // Turn-order-navigation-dialog scratch list, constructed in
  // InitializeTurnOrderNavigationDialogByViewportSize as a real TPtrList -- not a TView
  // (bd d9p: the port previously typed this TView* and reinterpret_cast'd a bare
  // TSortedPtrList onto it, which made TDisplayMgr::Free's call resolve to TView's
  // 0x28-slot vtable entry instead of the list's; fixed to call the real list method).
  TPtrList* turnOrderList; // +0x20

  TDisplayMgr();
};

// g_pDisplayMgr and UDisplayMgr font globals — see game/global_data_tables.h.
