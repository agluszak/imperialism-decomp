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
                                      void* eventDataB) override;

  void OrphanCallChain_C1_I08_0058c330(short value84, char refreshFlag);
  void OrphanCallChain_C2_I23_0058c360(short value86, char refreshFlag);
};
