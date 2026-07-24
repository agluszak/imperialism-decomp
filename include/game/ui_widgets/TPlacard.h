#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

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
  virtual bool SetValue(short value = -1, bool refreshNow = true);
};
ASSERT_SIZE(TPlacard, 0x94);
