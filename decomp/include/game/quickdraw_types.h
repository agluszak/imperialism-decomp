#pragma once

typedef int QuickDrawPaletteIndex;

struct CRGBColor {
  unsigned char red;
  unsigned char green;
  unsigned char blue;
  unsigned char reserved;

  CRGBColor();
  CRGBColor(unsigned short redValue, unsigned short greenValue, unsigned short blueValue);
};
