#pragma once

#include "game/TPictureResourceEntryBase.h"

extern "C" int g_vtblTPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTPlacard;

// VTABLE: IMPERIALISM 0x667218
class TPlacard : public TPictureResourceEntryBase {
public:
  short glyph90;
  short field92;

  TPlacard();
  virtual ~TPlacard() override;
  CRuntimeClass* GetRuntimeClass() override;

  void NoOpUiLifecycleHook(int arg) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  bool IsSelected(short value = -1, bool refreshNow = true) override;
};
