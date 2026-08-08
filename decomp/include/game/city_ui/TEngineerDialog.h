#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"

struct TQuickDrawSurfaceContext;

// Engineer-dialog view (university advanced status UI). Mac: TEngineerDialog::Free, Draw.
// VTABLE: IMPERIALISM 0x652d60
class TEngineerDialog : public TView {
public:
  // Offscreen QuickDraw surface contexts for the three dialog strips; each is released
  // through g_pDisplayMgr->RemoveGWorld and blitted via GetBlitSurface()
  // (its blit sub-object lives at +0x4). Were mis-modeled as raw unsigned char* buffers
  // reached with a `ctx + 4` cast.
  TQuickDrawSurfaceContext* headerSurface60;   // 0x60
  TQuickDrawSurfaceContext* footerSurface64;   // 0x64
  TQuickDrawSurfaceContext* bodyTileSurface68; // 0x68

  TEngineerDialog();
  virtual ~TEngineerDialog() override;

  DECLARE_DYNCREATE(TEngineerDialog)
  void Free() override;                 // 0x1c 0x4d05e0
  void Draw(RECT* rectBuffer) override; // 0x110 0x4d0650

  // Rebuilds the engineer/city-view production overlay for the region anchored at
  // nBuildingSlotId: reloads the three offscreen strip surfaces, retitles the panel,
  // aggregates per-resource capability/development counts over the tile and its six
  // hex neighbours (owned by the active nation, inside the city influence map), then
  // conditionally builds fort/rail/port up-down buttons with their TDeluxeText labels
  // and TIconBar amount rows, plus the cancel button. 0x004d0810, __thiscall.
  virtual void BuildCityViewProductionControls(short nBuildingSlotId); // slot 0x68
};
ASSERT_SIZE(TEngineerDialog, 0x6c);
