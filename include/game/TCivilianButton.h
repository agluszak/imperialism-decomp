#pragma once

#include "game/TRadioPictureButton.h"

extern "C" int g_vtblTCivilianButton;
extern "C" int g_pClassDescTCivilianButton;

// VTABLE: IMPERIALISM 0x666da8
class TCivilianButton : public TRadioPictureButton {
public:
  short mappedSelection98;
  short selectedValue9c;

  TCivilianButton();
  virtual ~TCivilianButton();
  
  void SetSelectionAndEnableByMappedValue(int selectedValue);
};
