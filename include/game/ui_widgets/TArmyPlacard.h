#pragma once

#include "game/ui_core/TPicture.h"

extern "C" int g_vtblTArmyPlacard;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x667448
class TArmyPlacard : public TPicture {
public:
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0058c140
  short glyph90;

  TArmyPlacard();
  virtual ~TArmyPlacard() override;
  DECLARE_DYNCREATE(TArmyPlacard)
  void Function_0058bc20();
  void RenderArmyPlacardWithShadow();
  void Draw(RECT* rectBuffer) override; // 0x110 0x58bfe0
  virtual void SetValue(short value = -1, unsigned char refreshNow = 1);
};
