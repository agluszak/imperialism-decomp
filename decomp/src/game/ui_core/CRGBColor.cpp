#include "game/quickdraw_types.h"

// FUNCTION: IMPERIALISM 0x0045b080
CRGBColor::CRGBColor() : red(0), green(0), blue(0), reserved(0) {}

// FUNCTION: IMPERIALISM 0x0045b0a0
CRGBColor::CRGBColor(unsigned short redValue, unsigned short greenValue, unsigned short blueValue) {
  red = static_cast<unsigned char>(redValue >> 8);
  green = static_cast<unsigned char>(greenValue >> 8);
  reserved = 0;
  blue = static_cast<unsigned char>(blueValue >> 8);
}
