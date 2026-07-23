#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006404b0
class TMapKey : public TPicture {
public:
  DECLARE_DYNCREATE(TMapKey)
  virtual ~TMapKey() override;                  // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4fcac0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fcf80
  // Legend/hint overlay render mode selector. TMapKey::Draw (0x4fcf80)
  // switches on this to pick one of the RenderMapHintOverlayMode* label passes.
  short viewMode90; // 0x90
  unsigned char padding92[2];

  TMapKey();

private:
  // Legend-label render passes dispatched by Draw (each draws its
  // localized labels twice for a drop shadow, via the QuickDraw text helpers).
  void RenderMapHintOverlayMode0(); // 0x004fd000
  void RenderMapHintOverlayMode1(); // 0x004fd5c0
  void RenderMapHintOverlayMode2(); // 0x004fd910
  void RenderMapHintOverlayMode4(); // 0x004fd220
};

ASSERT_SIZE(TMapKey, 0x94);
