#include "game/TCivAnimation2.h"

// SYNTHETIC: IMPERIALISM 0x0049f630
// TCivAnimation2::`scalar deleting destructor'
TCivAnimation2::~TCivAnimation2() {}
// SYNTHETIC: IMPERIALISM 0x0049f600
// TCivAnimation2::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f680
// TCivAnimation2::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivAnimation2, TAnimation)

TCivAnimation2::TCivAnimation2() {}

// FUNCTION: IMPERIALISM 0x0049f6a0
TCivAnimation2::TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag) {
  static const short kStringIds[9] = {14000, 14005, 14011, 14015, 14021,
                                      14026, 14030, 14035, 14040};
  static const int kTicksPerFrame[9] = {5, 15, 10, 7, 15, 15, 7, 10, 10};
  ConstructTAnimationBaseState(ownerView, rect, 0, kStringIds[kind], kTicksPerFrame[kind], tag);
  kindIndex2c = static_cast<short>(kind);
}

// FUNCTION: IMPERIALISM 0x0049f7c0
undefined TCivAnimation2::AdvanceAnimationTickAndInvalidateOnFrameFlip() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049f8e0
undefined TCivAnimation2::RenderBattleReportInsetWithPaletteShift() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0d10
void TCivAnimation2::AddObjectToUiTransientRegistry(TAnimation* animationObject) {
  (void)animationObject;
}

// FUNCTION: IMPERIALISM 0x004a0d30
void* TCivAnimation2::FindLinkedListNodeByIdFieldAt18(int nodeId) {
  // TODO(mfc-collections): real body iterates field_0x24's list (GetHeadPosition /
  // GetNext-shaped calls) comparing each node's +0x18 id field against nodeId. The
  // list/node classes aren't recovered yet.
  (void)nodeId;
  return nullptr;
}
