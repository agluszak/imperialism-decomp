#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TMapUberPicture;

// VTABLE: IMPERIALISM 0x00669170
class TMiniMapView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniMapView)
  virtual ~TMiniMapView() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
  TMapUberPicture* ownerPicture;
  int scrollTileColumn;
  int scrollTileRow;
  int markerBoxX;
  int markerBoxY;
  int markerBoxWidth;
  int markerBoxHeight;

  TMiniMapView();

  void IMiniMapView(TView* panel, int* offsetLayout, int* sizeLayout, int sizeDeterminerX,
                    int sizeDeterminerY);

  void SetScreenSize(const POINT& size) {
    markerBoxWidth = size.x;
    markerBoxHeight = size.y;
    markerBoxX = frameWidth / 2 - markerBoxWidth - 2;
    markerBoxY = frameHeight / 2 - markerBoxHeight - 2;
    RefreshControl();
  }
};
ASSERT_SIZE(TMiniMapView, 0xa0);
