#pragma once

#include "game/TControl.h"
#include "game/CString.h"

// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString text;
  void* field88;
  int field8C;
  int field90;

  TStaticText();
  virtual ~TStaticText();

  virtual CRuntimeClass* GetRuntimeClass(); // 0x00 0x48f870 (override)

  void DestroyStaticTextAndReleaseOwnedResources();
};
