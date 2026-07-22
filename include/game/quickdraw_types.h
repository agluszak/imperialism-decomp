#pragma once

// Palette-table identity used by the game-owned QuickDraw compatibility layer.
// TViewMgr::GetColor returns the full int form; 8-bpp pixel stores and legacy
// QuickDraw entry points narrow it explicitly at their representation boundary.
typedef int QuickDrawPaletteIndex;
