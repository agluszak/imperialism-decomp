#pragma once

#include "game/ui_core/TControl.h"

extern "C" int g_vtblTNumberedArrowButton;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x667678
class TNumberedArrowButton : public TControl {
public:
  short value84;
  short value86;

  TNumberedArrowButton();
  DECLARE_DYNCREATE(TNumberedArrowButton)
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* cursorPoint,
                                                           RgnHandle hitArg) override;
  void Draw(RECT* rectBuffer) override;
  void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint, CPoint& currentPoint,
                  unsigned char commandFlag) override;

  using TControl::SetState;
  virtual void SetValue(short value84, unsigned char refreshFlag); // slot 0x71 0x58c330
  void SetState(short value86, unsigned char refreshFlag);
};
