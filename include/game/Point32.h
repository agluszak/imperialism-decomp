#pragma once

// 32-bit screen/grid point (MFC POINT-shaped). Shared across UI translation
// units that previously each defined their own identical local copy.
struct Point32 {
  int x;
  int y;
};
