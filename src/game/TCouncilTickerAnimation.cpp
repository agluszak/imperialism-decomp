#include "game/TCouncilTickerAnimation.h"

#include "game/TAnimator.h"
#include "game/TCivAnimation2.h"
#include "game/TControl.h"
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
void TCouncilTickerAnimation::ConstructTCouncilTickerAnimationBaseState(void* hostPanel,
                                                                        int tickMode) {
  char* objectBytes = reinterpret_cast<char*>(this);
  *reinterpret_cast<void**>(objectBytes + 0x4) = hostPanel;
  *reinterpret_cast<unsigned short*>(objectBytes + 0x8) = 0;
  *reinterpret_cast<unsigned short*>(objectBytes + 0xa) = 0;
  *reinterpret_cast<unsigned short*>(objectBytes + 0xc) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x10) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x14) = static_cast<unsigned int>(tickMode);
  *reinterpret_cast<unsigned int*>(objectBytes + 0x18) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x1c) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x20) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x24) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x28) = 0;
}

// FUNCTION: IMPERIALISM 0x0049ffe0
undefined TCouncilTickerAnimation::AdvanceAnimationTickAndInvalidateOnFrameFlip() {
  return 0;
}
