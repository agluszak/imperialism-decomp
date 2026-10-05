#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// CONFIRMED REAL CLASS: RTTI CRuntimeClass descriptor `classTCivAnimation2` at
// 0x64c220 (DYNCREATE, symbols.csv row 7965) gives the true name and base edge
// TCivAnimation2 -> TAnimation -> TObject -> CObject; vtable @ 0x64c390 has 13
// distinct slots (not folded with TAnimation/TOneTimeAnimation), and it is
// upcast-constructed as a real object in TCouncilTickerAnimation.cpp
// (g_pUiAnimator) and TMapDialog.cpp. It is a battle-report civ animation
// state machine, not a misattribution.
// (AddAnimation 0x4a0d10 and the registry walker 0x4a0d30,
// once bucketed here by Ghidra, are really TAnimator methods -- the receiver
// is the g_pUiAnimator global, proven by the callers' `mov ecx,[0x6a43e0]`.)
// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation2)
  // FUNCTION: IMPERIALISM 0x0049f660
  virtual ~TCivAnimation2() override {}               // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;                       // slot 0x0a 0x49f7c0
  virtual void DrawNextFrame(POINT* offset) override; // slot 0x0b 0x49f8e0
  // TAnimation's own slice ends at 0x2c (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TCivAnimation2) == 0x30. Caches the ctor's `kind` selector (see the ctor
  // below) for later reference; real reader not yet identified.
  short kindIndex; // +0x2c
  short pad2e;     // +0x2e

  // NOOP: verified empty in original 0x0049f602 (no standalone TCivAnimation2::TCivAnimation2 body exists: construction is fully inlined into CreateObject 0x0049f600; that address is its operator-new call site)
  TCivAnimation2() {}

  // Forwards to TAnimation::IAnimation with no frames; Tick drives the animation itself.
  TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag);
};

ASSERT_SIZE(TCivAnimation2, 0x30);
