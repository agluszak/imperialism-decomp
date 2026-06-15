#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTPlacard;

// VTABLE: IMPERIALISM 0x667218
class TPlacard : public TPictureButton {
public:
  TPlacard();
  virtual ~TPlacard() override;
  CRuntimeClass* GetRuntimeClass() override;

  void NoOpUiLifecycleHook(int arg) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
};
