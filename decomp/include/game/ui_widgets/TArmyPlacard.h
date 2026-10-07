#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x667448
class TArmyPlacard : public TPicture {
public:
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  short glyph;

  TArmyPlacard();
  virtual ~TArmyPlacard() override;
  DECLARE_DYNCREATE(TArmyPlacard)
  void RenderArmyPlacardWithShadow();
  void Draw(RECT* rectBuffer) override;
  virtual void SetValue(short value = -1, bool refreshNow = 1);
};
ASSERT_SIZE(TArmyPlacard, 0x94);
