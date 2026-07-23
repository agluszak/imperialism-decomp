#pragma once

#include "compat.h"

#include "game/ui_widgets/TMapUberUberPicture.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TTacticalBattleView;

// VTABLE: IMPERIALISM 0x006451f0
class TTacMapUberPicture : public TMapUberUberPicture {
public:
  DECLARE_DYNCREATE(TTacMapUberPicture)
  virtual ~TTacMapUberPicture() override;                 // slot 0x01 (scalar deleting destructor)
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x5ad3f0
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x5ad3a0
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask) override; // slot 0x74 0x45d3b0

  TTacMapUberPicture();

  // Tactical 'DLOG' child resolved by DoPostCreate. Scroll forwards
  // the edge mask to its slot 0x6b
  // (TTacticalBattleView::Scroll).
  TTacticalBattleView* tacticalBattleView94;
};
ASSERT_SIZE(TTacMapUberPicture, 0x98);
