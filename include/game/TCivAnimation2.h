#pragma once

#include "game/TAnimation.h"
#include "game/mfc.h"

// CONFIRMED REAL CLASS: RTTI CRuntimeClass descriptor `classTCivAnimation2` at
// 0x64c220 (DYNCREATE, symbols.csv row 7965) gives the true name and base edge
// TCivAnimation2 -> TAnimation -> TObject -> CObject; vtable @ 0x64c390 has 13
// distinct slots (not folded with TAnimation/TOneTimeAnimation), and it is
// upcast-constructed as a real object in TCouncilTickerAnimation.cpp
// (g_pUiAnimator) and TMapDialog.cpp. It is a battle-report civ animation
// state machine, not a misattribution.
// TODO(manifest): field_0x24 is a polymorphic receiver called through vtable
// slot 0x30/4=12 in AddObjectToUiTransientRegistry (0x4a0d10) — needs class
// recovery (slice-discovery) to type; current body is a stub, not a real
// port. FindLinkedListNodeByIdFieldAt18 (0x4a0d30) is an orphaned real
// thiscall method on this class (walks a linked list of nodes each with an
// id field at +0x18) still living in autogen stubs as free-function
// `undefined4(void)` — needs promotion to a member + typed list.
// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  // === BEGIN GENERATED DECLS (TCivAnimation2) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCivAnimation2)
  virtual ~TCivAnimation2() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined AdvanceAnimationTickAndInvalidateOnFrameFlip() override; // slot 0x0a 0x49f7c0
  virtual undefined RenderBattleReportInsetWithPaletteShift() override;      // slot 0x0b 0x49f8e0
  // slot 0x0c RenderBattleReportViewSurfaceSpriteWithResourceHandle inherited unchanged (0x49f2d0)
  // === END GENERATED DECLS (TCivAnimation2) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TCivAnimation2 0xCTOR`).

  void AddObjectToUiTransientRegistry(TAnimation* animationObject);
  // Walks the field_0x24 list for a node whose id field (+0x18) matches nodeId; 0 if
  // this is null, the list is empty, or nothing matches. The list/node classes aren't
  // recovered yet (MFC-collection-shaped internals -- CPtrList-style iteration), so
  // the walk itself is left unmodeled. 0x4a0d30
  void* FindLinkedListNodeByIdFieldAt18(int nodeId);

  TCivAnimation2();
};
