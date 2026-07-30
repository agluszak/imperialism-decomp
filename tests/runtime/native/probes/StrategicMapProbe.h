#pragma once

#ifndef IMPERIALISM_STRATEGIC_MAP_PROBE_H
#define IMPERIALISM_STRATEGIC_MAP_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error StrategicMapProbe is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

// Pixel-level checks on the strategic map: that it drew what the atlas says it should, that
// hovering leaves no transient selection pixels in the map cache, and that scrolling reaches and
// wraps at each edge.
//
// A probe rather than part of StrategicMapScreen: these reach past the control tree into the map's
// render surface and compare captured pixels, which is not something a script's vocabulary should
// grow. Each resolves the map itself, so a script already on the map does not hand it over.
class StrategicMapProbe {
public:
  static RuntimeActionResult VerifyRendering();
  static RuntimeActionResult VerifyHoverCache();
  static RuntimeActionResult VerifyScrolling();
};

#endif
