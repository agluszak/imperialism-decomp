#pragma once

#include "game/TAnimation.h"
#include "game/mfc.h"

// TODO(manifest): describe TCivAnimation2 and its role. Base edge (TAnimation) recovered from RTTI CRuntimeClass chain: TCivAnimation2 -> TAnimation -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
// === BEGIN GENERATED DECLS (TCivAnimation2) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCivAnimation2)
  virtual ~TCivAnimation2(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_InvalidateCityDialogRectRegion_At0049f140() override; // slot 0x0a 0x49f7c0
  virtual undefined RenderBattleReportInsetWithPaletteShift() override; // slot 0x0b 0x49f8e0
  // slot 0x0c RenderBattleReportViewSurfaceSpriteWithResourceHandle inherited unchanged (0x49f2d0)
// === END GENERATED DECLS (TCivAnimation2) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TCivAnimation2 0xCTOR`).

  TCivAnimation2();
};

// === BEGIN GENERATED (TCivAnimation2) — refreshed by `just gen-class TCivAnimation2`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c390 (13 slots), object size 0x30, base TAnimation
//   slot 0x00  byte 0x00  0x0049f680  override  GetTAnimationClassNamePointer
//   slot 0x01  byte 0x04  0x0049f630  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0049f7c0  override  VTableSlot0A
//   slot 0x0b  byte 0x2c  0x0049f8e0  override  RenderBattleReportInsetWithPaletteShift
//   slot 0x0c  byte 0x30  0x0049f2d0  inherited RenderBattleReportViewSurfaceSpriteWithResourceHandle
// object size 0x30 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCivAnimation2) ===
