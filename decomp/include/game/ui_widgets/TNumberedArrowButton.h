#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x667678
class TNumberedArrowButton : public TControl {
public:
  // FUNCTION: IMPERIALISM 0x0058c310
  ~TNumberedArrowButton() override {}
  short number;
  short arrowState;

  TNumberedArrowButton();
  DECLARE_DYNCREATE(TNumberedArrowButton)
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* cursorPoint,
                                                           RgnHandle hitArg) override;
  void Draw(RECT* rectBuffer) override;
  void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint, CPoint& currentPoint,
                  bool commandFlag) override;

  virtual void SetValue(short value84, bool refreshFlag); // slot 0x71 0x58c330
  void SetState(short value86, unsigned char refreshFlag);
};
ASSERT_SIZE(TNumberedArrowButton, 0x88);
