#pragma once

// Palette-table identity used by the game-owned QuickDraw compatibility layer.
// TViewMgr::GetColor returns the full int form; 8-bpp pixel stores and legacy
// QuickDraw entry points narrow it explicitly at their representation boundary.
typedef int QuickDrawPaletteIndex;

// Four-byte Windows representation of the cross-platform CRGBColor helper. The
// 16-bit QuickDraw components retain their high byte, matching the retail stores.
struct CRGBColor {
  unsigned char red;
  unsigned char green;
  unsigned char blue;
  unsigned char reserved;

  CRGBColor();
  CRGBColor(unsigned short redValue, unsigned short greenValue, unsigned short blueValue);
};
