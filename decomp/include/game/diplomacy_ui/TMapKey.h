#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006404b0
class TMapKey : public TPicture {
public:
  DECLARE_DYNCREATE(TMapKey)
  virtual ~TMapKey() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  short viewMode;
  unsigned char padding92[2];

  TMapKey();

private:
  void RenderMapHintOverlayMode0();
  void RenderMapHintOverlayMode1();
  void RenderMapHintOverlayMode2();
  void DrawTreatyPanel();
};

ASSERT_SIZE(TMapKey, 0x94);
