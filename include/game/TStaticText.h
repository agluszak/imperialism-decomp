#pragma once

#include "game/TControl.h"
#include "game/CString.h"

// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString field84;
  void* field16_0x88;
  int field17_0x8c;
  int field18_0x90;

  TStaticText();
  virtual ~TStaticText();

  void DestroyStaticTextAndReleaseOwnedResources();
};
