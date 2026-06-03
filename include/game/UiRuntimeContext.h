#pragma once

// Global UI runtime context (active-nation / palette state) shared by the widget
// and trade-screen code. Extracted from ui_widget_shared.h.

#include "decomp_types.h"

struct UiRuntimeContext {
  void* vftable;
  char pad_04[0x2a];
  short activeNationIdAt2E;

  short GetActiveNationId(void);
  int MapTurnEventCodeToPaletteIndex(int eventCode);
};

extern "C" UiRuntimeContext* g_pUiRuntimeContext;
