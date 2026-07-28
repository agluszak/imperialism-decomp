#include "game/app/TCouncilTickerAnimation.h"

#include "game/app/TAnimator.h"
#include "game/app/TCivAnimation2.h"
#include "game/ui_core/TControl.h"
#include "game/diplomacy_ui/TCouncilView.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0049ff20
// TCouncilTickerAnimation::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049ff50
TCouncilTickerAnimation::~TCouncilTickerAnimation() {}
// SYNTHETIC: IMPERIALISM 0x0049fef0
// TCouncilTickerAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049ff70
// TCouncilTickerAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCouncilTickerAnimation, TAnimation)

// FUNCTION: IMPERIALISM 0x0049ff90
void TCouncilTickerAnimation::InitializeCouncilTicker(TCouncilView* hostPanel, int tickInterval) {
  ownerView = hostPanel;
  frameIndex = 0;
  frameCount = 0;
  frameResourceBaseId = 0;
  ticksSinceFrameChange = 0;
  ticksPerFrame = tickInterval;
  registryTag = 0;
  screenRect.left = 0;
  screenRect.top = 0;
  screenRect.right = 0;
  screenRect.bottom = 0;
}

// FUNCTION: IMPERIALISM 0x0049ffe0
void TCouncilTickerAnimation::Tick() {
  int tick = ticksSinceFrameChange + 1;
  ticksSinceFrameChange = tick;
  if (tick == ticksPerFrame) {
    static_cast<TCouncilView*>(ownerView)->NextTick();
    ticksSinceFrameChange = 0;
  }
}
