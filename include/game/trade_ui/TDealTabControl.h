#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641168
class TDealTabControl : public TControl {
public:
  DECLARE_DYNCREATE(TDealTabControl)
  virtual ~TDealTabControl() override;          // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x5bcb20
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5bc7f0
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override;                // slot 0x68 0x5bc9f0
  virtual void Setup(short bitmapResourceId, unsigned char useAlternatePair); // slot 0x71 0x5bc780
  // Vertical fill-bar slice read by Draw: negative selectedRow84 means "no
  // selection" (draw the whole strip empty); otherwise the highlight band spans
  // [selectedRow84*rowHeightPx86, +rowHeightPx86) with the empty strip above and below.
  short selectedRow84; // +0x84 selected row index, -1 = none
  short rowHeightPx86; // +0x86 pixel height of one row
  short tabCount88;    // +0x88 Setup default: 15
  short padding8A;
  struct TQuickDrawSurfaceContext* filledRowStrip8c; // +0x8c highlighted-row strip
  struct TQuickDrawSurfaceContext* emptyRowStrip90;  // +0x90 background strip

  TDealTabControl();
};
