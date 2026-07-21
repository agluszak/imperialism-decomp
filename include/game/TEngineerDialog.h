#pragma once

#include "game/TView.h"

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
};
