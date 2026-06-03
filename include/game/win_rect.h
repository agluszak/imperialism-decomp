#pragma once

// Win32 RECT plus the two USER32 rect helpers used throughout the widget code.
// Extracted from ui_widget_shared.h.

struct RECT {
  int left;
  int top;
  int right;
  int bottom;
};

extern "C" int __stdcall CopyRect(RECT* destination, const RECT* source);
extern "C" int __stdcall OffsetRect(RECT* rect, int dx, int dy);
