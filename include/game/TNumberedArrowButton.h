#pragma once

#include "game/TControl.h"

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
                                                           int hitArg) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  void DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                      void* eventDataB, int commandFlag) override;

  using TControl::SetState;
  virtual void SetValue(short value84, unsigned char refreshFlag); // slot 0x71 0x58c330
  void SetState(short value86, unsigned char refreshFlag);
};
