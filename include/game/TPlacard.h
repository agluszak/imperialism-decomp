#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTPlacard;
extern "C" int g_pClassDescTPlacard;

// VTABLE: IMPERIALISM 0x667238
class TPlacard : public TPictureButton {
public:
  TPlacard();
  virtual ~TPlacard();

  void RenderRightAlignedNumericOverlayWithShadow();

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0();
  void WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50(int arg1, int arg2);
  void RenderPlacardValueTextWithShadow();
};
