#include "game/TCouncilTickerAnimation.h"

#include "game/TAnimator.h"
#include "game/TCivAnimation2.h"
#include "game/TControl.h"
#include "game/TCouncilView.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TPicture.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/TDiplomacyMgr.h"
#include "game/TSimMgr.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0049ff20
// TCouncilTickerAnimation::`scalar deleting destructor'
TCouncilTickerAnimation::~TCouncilTickerAnimation() {}
// SYNTHETIC: IMPERIALISM 0x0049fef0
// TCouncilTickerAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049ff70
// TCouncilTickerAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCouncilTickerAnimation, TAnimation)

TCouncilTickerAnimation::TCouncilTickerAnimation() {}

// FUNCTION: IMPERIALISM 0x0049ff90
void TCouncilTickerAnimation::ConstructTCouncilTickerAnimationBaseState(TCouncilView* hostPanel,
                                                                        int tickInterval) {
  ownerView04 = hostPanel;
  frameIndex08 = 0;
  frameCount0A = 0;
  field0C = 0;
  tickCounter10 = 0;
  ticksPerFrame14 = tickInterval;
  registryTag18 = 0;
  screenRect1C.left = 0;
  screenRect1C.top = 0;
  screenRect1C.right = 0;
  screenRect1C.bottom = 0;
}

// FUNCTION: IMPERIALISM 0x0049ffe0
undefined TCouncilTickerAnimation::AdvanceAnimationTickAndInvalidateOnFrameFlip() {
  int tick = tickCounter10 + 1;
  tickCounter10 = tick;
  if (tick == ticksPerFrame14) {
    static_cast<TCouncilView*>(ownerView04)->AdvanceCivilianTerrainSelectionStep();
    tickCounter10 = 0;
  }
  return static_cast<undefined>(tick);
}
