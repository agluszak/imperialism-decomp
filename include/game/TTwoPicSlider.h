#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x00641bd0
class TTwoPicSlider : public TControl {
public:
  int lowerSurface;     // 0x84
  int upperSurface;     // 0x88
  int compositeSurface; // 0x8C
  short splitPosition;  // 0x90
  unsigned char pad92[2];
  int mode; // 0x94

  TTwoPicSlider();
  virtual ~TTwoPicSlider();

  void DrawTwoPicSliderSplitOverlayAndCenteredStatusText();
  void TrackTwoPicSliderMouseAndRefresh(int inputPhase, void* param2, int pointRecord);
};
