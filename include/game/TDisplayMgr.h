#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TDisplayMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TDisplayMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00656680
class TDisplayMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TDisplayMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4fe780
  virtual ~TDisplayMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4fea60
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined InitializeTurnOrderNavigationDialogByViewportSize(); // slot 0x0a 0x4fe840
  virtual undefined Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(); // slot 0x0b 0x4feab0
  virtual undefined EnsurePrimaryRenderSurfaceContextAllocated(); // slot 0x0c 0x4feb80
  virtual undefined WrapperFor_thunk_NoOpCallback_00498ca0_At004febd0(); // slot 0x0d 0x4febd0
  virtual undefined WrapperFor_thunk_NoOpCallback_00498ca0_At004fed00(); // slot 0x0e 0x4fed00
  virtual undefined OrphanRetStub_004fed50(); // slot 0x0f 0x4fed50
  virtual undefined AssertUDisplayMgrLines614And616(char param_1); // slot 0x10 0x4fed70
  virtual undefined AssertUDisplayMgrLine471(); // slot 0x11 0x4fec20
  virtual undefined AssertUDisplayMgrLine495(); // slot 0x12 0x4fec50
  virtual undefined DispatchDisplayManagerControlStringMessage(); // slot 0x13 0x4fec80
  virtual undefined LoadMainViewClipSnapshotIntoQuickDrawState(undefined2 param_1); // slot 0x14 0x4fedc0
  virtual undefined SetMapTileIconVariantTriplet(undefined1 * param_1); // slot 0x15 0x4fefc0
  virtual undefined DispatchUiWindowStatusTickForClass99Windows(); // slot 0x16 0x4ff000
// === END GENERATED DECLS (TDisplayMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TDisplayMgr 0xCTOR`).

  TDisplayMgr();
};

// === BEGIN GENERATED (TDisplayMgr) — refreshed by `just gen-class TDisplayMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x00656680 (23 slots), object size 0x24, base TObject
//   slot 0x00  byte 0x00  0x004fe780  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004fe7f0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004fea60  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004fe840  override  InitializeTurnOrderNavigationDialogByViewportSize
//   slot 0x0b  byte 0x2c  0x004feab0  override  Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0
//   slot 0x0c  byte 0x30  0x004feb80  override  EnsurePrimaryRenderSurfaceContextAllocated
//   slot 0x0d  byte 0x34  0x004febd0  override  WrapperFor_thunk_NoOpCallback_00498ca0_At004febd0
//   slot 0x0e  byte 0x38  0x004fed00  override  WrapperFor_thunk_NoOpCallback_00498ca0_At004fed00
//   slot 0x0f  byte 0x3c  0x004fed50  override  OrphanRetStub_004fed50
//   slot 0x10  byte 0x40  0x004fed70  override  AssertUDisplayMgrLines614And616
//   slot 0x11  byte 0x44  0x004fec20  override  AssertUDisplayMgrLine471
//   slot 0x12  byte 0x48  0x004fec50  override  AssertUDisplayMgrLine495
//   slot 0x13  byte 0x4c  0x004fec80  override  DispatchDisplayManagerControlStringMessage
//   slot 0x14  byte 0x50  0x004fedc0  override  LoadMainViewClipSnapshotIntoQuickDrawState
//   slot 0x15  byte 0x54  0x004fefc0  override  SetMapTileIconVariantTriplet
//   slot 0x16  byte 0x58  0x004ff000  override  DispatchUiWindowStatusTickForClass99Windows
// object size 0x24 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TDisplayMgr) ===
