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
  virtual ~TTacMapUberPicture() override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask) override;

  TTacMapUberPicture() : tacticalBattleView(NULL) {}

  void SetWindPictureResourceIdAndRefresh(int resourceBase);

  TTacticalBattleView* tacticalBattleView;
};
ASSERT_SIZE(TTacMapUberPicture, 0x98);
