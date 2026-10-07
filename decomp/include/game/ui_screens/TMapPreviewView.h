#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x006419d8
class TMapPreviewView : public TView {
public:
  DECLARE_DYNCREATE(TMapPreviewView)
  virtual ~TMapPreviewView() override;
  virtual void Free() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  TMapPreviewView();

  void TakeSatellitePhoto(char* tileOwnerTagTable);
  // Rebuild the selected-nation boundary mask in the offscreen preview surface.
  void EnhancePhoto();

  TQuickDrawSurfaceContext* previewSurface;
  int selectedRegion; // city/region marker; ctor seeds -1 (none)
  int selectedNation; // nation whose boundary is highlighted (-1 = none)
  int pendingNation;  // nation hit by the most recent mouse command
};
ASSERT_SIZE(TMapPreviewView, 0x70);
