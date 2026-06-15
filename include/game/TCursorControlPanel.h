#pragma once

#include "game/TControl.h"

class TCursorControlPanel : public TControl {
public:
  // Slots 113-127 (0x1C4-0x1FC)
  virtual void dummy_113() = 0;
  virtual void dummy_114() = 0;
  virtual void dummy_115() = 0;
  virtual void dummy_116() = 0;
  virtual void dummy_117() = 0;
  virtual void dummy_118() = 0;
  virtual void dummy_119() = 0;
  virtual void dummy_120() = 0;
  virtual void dummy_121() = 0;
  virtual void dummy_122() = 0;
  virtual void dummy_123() = 0;
  virtual void dummy_124() = 0;
  virtual void dummy_125() = 0;
  virtual void dummy_126() = 0;
  virtual void dummy_127() = 0;

  // Slot 128 (0x200)
  virtual void UpdateCursorState() = 0;
};
