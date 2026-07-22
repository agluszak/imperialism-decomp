#pragma once

#include "game/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x006419d8
class TMapPreviewView : public TView {
public:
  DECLARE_DYNCREATE(TMapPreviewView)
  virtual ~TMapPreviewView() override;          // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x5789b0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x578850
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x578a80
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x5789e0

  TMapPreviewView();

  // Rasterize the owner-nation map into the offscreen preview surface. A non-null
  // table supplies one signed owner tag per map tile; null uses the live map state.
  void TakeSatellitePhoto(char* tileOwnerTagTable); // 0x578c10
  // Rebuild the selected-nation boundary mask in the offscreen preview surface.
  void EnhancePhoto(); // 0x579270

  // 0x60 — offscreen preview surface; deleted+cleared in Free (0x5789b0).
  TQuickDrawSurfaceContext* previewSurface60;
  int selectedRegion64; // 0x64 — city/region marker; ctor seeds -1 (none)
  int selectedNation68; // 0x68 — nation whose boundary is highlighted (-1 = none)
  int pendingNation6C;  // 0x6c — nation hit by the most recent mouse command
};
ASSERT_SIZE(TMapPreviewView, 0x70);
