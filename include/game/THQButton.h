#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTHQButton;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTHQButton;

// VTABLE: IMPERIALISM 0x666fe0
class THQButton : public TPictureButton {
public:
  short glyph94;
  short glyph96;
  short glyph98;
  char pad_9a[2];

  THQButton();
  virtual ~THQButton();
  CRuntimeClass* GetRuntimeClass() override;
};
