#pragma once

#include "game/TPicture.h"

extern "C" int g_vtblTPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTPlacard;

// VTABLE: IMPERIALISM 0x667218
class TPlacard : public TPicture {
public:
  short glyph90;
  short field92;

  TPlacard();
  virtual ~TPlacard() override;
  DECLARE_DYNCREATE(TPlacard)
  void NoOpUiLifecycleHook(int arg) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual bool IsSelected(short value = -1, bool refreshNow = true);
};
