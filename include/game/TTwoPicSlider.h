#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641bd0
class TTwoPicSlider : public TControl {
public:
  DECLARE_DYNCREATE(TTwoPicSlider)
  virtual ~TTwoPicSlider() override;
  virtual void Free() override; // slot 0x07 0x0056e2f0
  virtual void DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                              void* pEventDataA,
                                              void* pEventDataB) override; // slot 0x68 0x0056e640
  virtual void ApplyRectSlot110(RECT* rectBuffer) override; // slot 0x44 0x0056e370

  int lowerSurface;     // 0x84
  int upperSurface;     // 0x88
  int compositeSurface; // 0x8C
  short splitPosition;  // 0x90
  unsigned char pad92[2];
  int mode; // 0x94

  TTwoPicSlider();

  void InitializePictureSurfaces(int baseBitmapId); // 0x0056e200
};
