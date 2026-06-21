#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TAnimation and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TAnimation -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c300
class TAnimation : public TObject {
public:
// === BEGIN GENERATED DECLS (TAnimation) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x49f0a0
  virtual ~TAnimation(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_InvalidateCityDialogRectRegion_At0049f140() override; // slot 0x0a 0x49f140
  virtual undefined RenderBattleReportInsetWithPaletteShift() override; // slot 0x0b 0x49f190
  virtual undefined RenderBattleReportViewSurfaceSpriteWithResourceHandle() override; // slot 0x0c 0x49f2d0
  // These three are regular (non-virtual) methods — the orig TAnimation vtable
  // ends at byte 0x30; declaring them virtual appended 3 phantom slots.
  undefined EnsureBitmapResourceLoadedAndCopyRectSize(); // 0x495b70
  undefined WrapperFor_thunk_DecrementDialogResourceRefCountByShortIdAndCleanup_At00495c00(); // 0x495c00
  undefined WrapperFor_thunk_TemporarilyClearAndRestoreUiInvalidationFlag_At004a1100(); // 0x4a1100
// === END GENERATED DECLS (TAnimation) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TAnimation 0xCTOR`).

  TAnimation();
};

// === BEGIN GENERATED (TAnimation) — refreshed by `just gen-class TAnimation`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c300 (19 slots), object size 0x2c, base TObject
//   slot 0x00  byte 0x00  0x0049f0a0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0049f050  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0049f140  override  WrapperFor_InvalidateCityDialogRectRegion_At0049f140
//   slot 0x0b  byte 0x2c  0x0049f190  override  RenderBattleReportInsetWithPaletteShift
//   slot 0x0c  byte 0x30  0x0049f2d0  override  RenderBattleReportViewSurfaceSpriteWithResourceHandle
//   slot 0x0d  byte 0x34  0x00000000  null      (null)
//   slot 0x0e  byte 0x38  0x00000000  null      (null)
//   slot 0x0f  byte 0x3c  0x00000000  null      (null)
//   slot 0x10  byte 0x40  0x00495b70  override  EnsureBitmapResourceLoadedAndCopyRectSize
//   slot 0x11  byte 0x44  0x00495c00  override  WrapperFor_thunk_DecrementDialogResourceRefCountByShortIdAndCleanup_At00495c00
//   slot 0x12  byte 0x48  0x004a1100  override  WrapperFor_thunk_TemporarilyClearAndRestoreUiInvalidationFlag_At004a1100
// object size 0x2c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAnimation) ===
