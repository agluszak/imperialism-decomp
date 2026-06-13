#pragma once

#include "decomp_types.h"

typedef void* hwnd_t;

// Native window/screen host object pointed to by TView::field50. The member at +0x1C is
// the Win32 HWND used for ValidateRect/InvalidateRect/GetDC. Only the HWND slot is
// recovered so far; the rest is opaque padding.
struct TViewNativeWindow {
  unsigned char pad_00_to_1b[0x1c];
  hwnd_t hwnd; // 0x1c
};
