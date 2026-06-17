#pragma once

#include "game/TControl.h"
#include "game/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString text;   // 0x84
  void* field88;  // 0x88
  int field8C;    // 0x8c
  int field90;    // 0x90

  TStaticText();
  virtual ~TStaticText() override;

  virtual CRuntimeClass* GetRuntimeClass() const override; // 0x00 0x48f870

  TObject* ShallowClone() override;                 // 0x20 0x48fc00
  void ApplyRectSlot110(RECT* rectBuffer) override; // 0x110 0x48ffb0

  void DestroyStaticTextAndReleaseOwnedResources();
};
