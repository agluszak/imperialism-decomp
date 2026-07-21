#pragma once

#include "game/TPicture.h"

extern "C" int g_vtblTPlacard;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x667218
class TPlacard : public TPicture {
public:
  short glyph90;
  short reserved92;

  TPlacard();
  virtual ~TPlacard() override;
  DECLARE_DYNCREATE(TPlacard)
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  virtual bool IsSelected(short value = -1, bool refreshNow = true);
};
