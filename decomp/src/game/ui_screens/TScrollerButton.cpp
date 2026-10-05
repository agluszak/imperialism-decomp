#include "game/ui_screens/TScrollerButton.h"

IMPLEMENT_DYNCREATE(TScrollerButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00574f40
TScrollerButton::TScrollerButton() {}

// FUNCTION: IMPERIALISM 0x00574fa0
TScrollerButton::~TScrollerButton() {}

// FUNCTION: IMPERIALISM 0x00574fc0
void TScrollerButton::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                 CPoint& currentPoint, bool commandFlag) {
  (void)commandFlag;
}
