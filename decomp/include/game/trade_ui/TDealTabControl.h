#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641168
class TDealTabControl : public TControl {
public:
  DECLARE_DYNCREATE(TDealTabControl)
  virtual ~TDealTabControl() override;
  virtual void Free() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
  virtual void Setup(short bitmapResourceId, unsigned char useAlternatePair);
  short selectedRow;                               // selected row index, -1 = none
  short rowHeightPixels;                           // pixel height of one row
  short tabCount;                                  // Setup default: 15
  struct TQuickDrawSurfaceContext* filledRowStrip; // highlighted-row strip
  struct TQuickDrawSurfaceContext* emptyRowStrip;  // background strip

#ifdef IMPERIALISM_RUNTIME_TESTS
  bool ActivateRow(short row);
#endif

  // NOOP: verified empty in original 0x005bc6c8
  TDealTabControl() {}
};
ASSERT_SIZE(TDealTabControl, 0x94);
