#pragma once

#include "game/TRadioPictureButton.h"

extern "C" int g_vtblTCivilianButton;
class TCivUnit;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x666da8
class TCivilianButton : public TRadioPictureButton {
public:
  short mappedSelection98;
  short reserved9a;
  TCivUnit* selectedCivilianOrder9c;

  TCivilianButton();
  virtual ~TCivilianButton() override;
  DECLARE_DYNCREATE(TCivilianButton)
  void Draw(RECT* rectBuffer) override;

  void SetSelectedCivilianOrderAndEnableButton(TCivUnit* selectedOrder);
};
