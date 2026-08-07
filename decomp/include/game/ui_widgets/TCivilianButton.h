#pragma once

#include "compat.h"

#include "game/ui_screens/TRadioPictureButton.h"

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

  virtual void SetSelectedCivilianOrderAndEnableButton(
      TCivUnit* selectedOrder); // slot 0x75 0x58b460; Mac: SetButton(TCivUnit*)
};
ASSERT_SIZE(TCivilianButton, 0xa0);
