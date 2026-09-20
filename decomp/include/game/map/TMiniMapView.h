#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TMapUberPicture;

// A small world-map thumbnail with a highlighted viewport-marker box (see
// Draw/TrackMouse). Constructed by
// TMapUberPicture::DisplayMiniMap (0x599cf0), which stores the new instance
// into the owner's miniMapViewC0.
// VTABLE: IMPERIALISM 0x00669170
class TMiniMapView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniMapView)
  virtual ~TMiniMapView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x59a540
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x59a920
  // TControl ends at 0x84; this object's own slice runs 0x84-0x9f (object size 0xa0).
  // Owning TMapUberPicture backref -- set by DisplayMiniMap right after
  // construction (not by the ctor itself; ctor leaves it untouched).
  TMapUberPicture* ownerPicture84;
  // Tile-column/row scroll offset on the strategic map (Draw/
  // TrackMouse evidence; those bodies aren't ported yet).
  int scrollTileColumn88;
  int scrollTileRow8c;
  // Centered viewport-marker-box draw position, recomputed whenever frameWidth34/frameHeight38 or
  // the box size (below) change.
  int markerBoxX90;
  int markerBoxY94;
  // Viewport-marker-box size; ctor default is (*0x6a460c, 8), later resized to (0x20,
  // 0x1c) by DisplayMiniMap's refresh path.
  int markerBoxWidth98;
  int markerBoxHeight9c;

  TMiniMapView();

  // Mac oracle: IMiniMapView(TView*, const VPoint&, const VPoint&, SizeDeterminer,
  // SizeDeterminer). Second-phase init; the two SizeDeterminer args are dead on
  // Windows (4,4 forwarded literally). Dead standalone COMDAT at 0x0059a440.
  void IMiniMapView(TView* panel, int* offsetLayout, int* sizeLayout, int sizeDeterminerX,
                    int sizeDeterminerY);

  // Mac oracle: SetScreenSize(VPoint&). Retail retains a dead standalone COMDAT at
  // 0x0059a4c0; the live sites in TMapUberPicture carry the same field sequence
  // inline (VC5 declines to inline this body in the recomp TUs).
  // SYNTHETIC: IMPERIALISM 0x0059a4c0
  // TMiniMapView::SetScreenSize
  void SetScreenSize(const POINT& size) {
    markerBoxWidth98 = size.x;
    markerBoxHeight9c = size.y;
    markerBoxX90 = frameWidth34 / 2 - markerBoxWidth98 - 2;
    markerBoxY94 = frameHeight38 / 2 - markerBoxHeight9c - 2;
    RefreshControl();
  }
};
ASSERT_SIZE(TMiniMapView, 0xa0);
