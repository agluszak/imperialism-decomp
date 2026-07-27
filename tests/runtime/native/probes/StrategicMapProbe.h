#pragma once

#include "game/mfc.h"

class TMapUberPicture;

class StrategicMapProbe {
public:
  static bool VerifyRendering(TMapUberPicture* mapView, CString& failure);
  static bool VerifyHoverCache(TMapUberPicture* mapView, CString& failure);
  static bool VerifyScrolling(TMapUberPicture* mapView, CString& failure);
};
