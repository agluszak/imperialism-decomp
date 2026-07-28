#pragma once

#include "compat.h"

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
  // Vertical fill-bar slice read by Draw: negative selectedRow means "no
  // selection" (draw the whole strip empty); otherwise the highlight band spans
  // [selectedRow*rowHeightPixels, +rowHeightPixels) with the empty strip above and below.
  short selectedRow;     // +0x84 selected row index, -1 = none
  short rowHeightPixels; // +0x86 pixel height of one row
  short tabCount;        // +0x88 Setup default: 15
  short padding8A;
  struct TQuickDrawSurfaceContext* filledRowStrip; // +0x8c highlighted-row strip
  struct TQuickDrawSurfaceContext* emptyRowStrip;  // +0x90 background strip

  // NOOP: verified empty in original 0x005bc6c8 (no standalone TDealTabControl::TDealTabControl body exists: CreateObject 0x005bc690 inlines this default ctor, calling the TControl base ctor directly at that site)
  TDealTabControl() {}
};
ASSERT_SIZE(TDealTabControl, 0x94);
