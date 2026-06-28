#pragma once

#include "game/TAnimation.h"
#include "game/mfc.h"

// TODO(manifest): describe TCouncilTickerAnimation and its role. Base edge (TAnimation) recovered from RTTI CRuntimeClass chain: TCouncilTickerAnimation -> TAnimation -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c410
class TCouncilTickerAnimation : public TAnimation {
public:
// === BEGIN GENERATED DECLS (TCouncilTickerAnimation) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCouncilTickerAnimation)
  virtual ~TCouncilTickerAnimation(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_InvalidateCityDialogRectRegion_At0049f140() override; // slot 0x0a 0x49ffe0
  // slot 0x0b RenderBattleReportInsetWithPaletteShift inherited unchanged (0x49f190)
  // slot 0x0c RenderBattleReportViewSurfaceSpriteWithResourceHandle inherited unchanged (0x49f2d0)
// === END GENERATED DECLS (TCouncilTickerAnimation) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TCouncilTickerAnimation 0xCTOR`).

  void InitializeDiplomacyCouncilViewControlsAndTicker();
  void ConstructTCouncilTickerAnimationBaseState(void* hostPanel, int tickMode);

  TCouncilTickerAnimation();
};

// === BEGIN GENERATED (TCouncilTickerAnimation) — refreshed by `just gen-class TCouncilTickerAnimation`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c410 (13 slots), object size 0x2c, base TAnimation
//   slot 0x00  byte 0x00  0x0049ff70  override  GetTAnimationClassNamePointer
//   slot 0x01  byte 0x04  0x0049ff20  override  WrapperFor_FreeHeapBufferIfNotNull_At0049ff20
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0049ffe0  override  TickAndAdvanceCivilianTerrainSelectionStep
//   slot 0x0b  byte 0x2c  0x0049f190  inherited RenderBattleReportInsetWithPaletteShift
//   slot 0x0c  byte 0x30  0x0049f2d0  inherited RenderBattleReportViewSurfaceSpriteWithResourceHandle
// object size 0x2c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCouncilTickerAnimation) ===
