#pragma once

// Global UI runtime context (active-nation / palette state) shared by the widget
// and trade-screen code. Extracted from ui_widget_shared.h.

#include "decomp_types.h"

struct UiRuntimeContext {
  virtual void dummy00() = 0;
  virtual void dummy04() = 0;
  virtual void dummy08() = 0;
  virtual void dummy0C() = 0;
  virtual void dummy10() = 0;
  virtual void dummy14() = 0;
  virtual void dummy18() = 0;
  virtual void dummy1C() = 0;
  virtual void dummy20() = 0;
  virtual void dummy24() = 0;
  virtual void dummy28() = 0;
  virtual void dummy2C() = 0;
  virtual void dummy30() = 0;
  virtual void ApplyLegendSplitSlot34(int split) = 0; // 0x34
  virtual void dummy38() = 0;
  virtual void dummy3c() = 0;
  virtual void dummy40() = 0;
  virtual void dummy44() = 0;
  virtual void dummy48() = 0;
  virtual void DispatchEventSlot4C(short eventCode, int payload) = 0; // 0x4c
  virtual void dummy50() = 0;
  virtual short QueryUiScreenModeSlot54() = 0; // 0x54
  virtual void dummy58() = 0;
  virtual void dummy5c() = 0;
  virtual void dummy60() = 0;
  virtual void dummy64() = 0;
  virtual void ApplyUiRuntimeSlot68(int modeValue) = 0; // 0x68
  virtual void dummy6c() = 0;
  virtual void dummy70() = 0;
  virtual void dummy74() = 0;
  virtual void dummy78() = 0;
  virtual void dummy7c() = 0;
  virtual void dummy80() = 0;
  virtual void dummy84() = 0;
  virtual void dummy88() = 0;
  virtual void dummy8c() = 0;
  virtual void dummy90() = 0;
  virtual void dummy94() = 0;
  virtual void dummy98() = 0;
  virtual void dummy9c() = 0;
  virtual void dummya0() = 0;
  virtual void dummya4() = 0;
  virtual void dummya8() = 0;
  // slot 0xac — city production UI refresh after order quantity change.
  virtual void RefreshCityProductionUiSlotAc() = 0;

  // Data layout. The C++ vptr occupies offset 0, matching the native object's
  // vtable pointer; explicit fields follow.
  char pad_04[0x2a];
  short activeNationIdAt2E;

  short GetActiveNationId(void);
  int MapTurnEventCodeToPaletteIndex(int eventCode);

protected:
  ~UiRuntimeContext() {}
};

extern "C" UiRuntimeContext* g_pUiRuntimeContext;
