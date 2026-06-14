#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTPlacard;

// VTABLE: IMPERIALISM 0x667238
class TPlacard : public TPictureButton {
public:
  TPlacard();
  virtual ~TPlacard() override;
  CRuntimeClass* GetRuntimeClass() override;

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0();
  void WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50(int arg1, int arg2);
  void RenderPlacardValueTextWithShadow();
};
