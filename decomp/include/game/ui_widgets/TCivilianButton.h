#pragma once

#include "compat.h"

#include "game/ui_screens/TRadioPictureButton.h"

class TCivUnit;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x666da8
class TCivilianButton : public TRadioPictureButton {
public:
  short mappedSelection;
  short reserved9a;
  TCivUnit* selectedCivilianOrder;

  TCivilianButton();
  virtual ~TCivilianButton() override;
  DECLARE_DYNCREATE(TCivilianButton)
  void Draw(RECT* rectBuffer) override;

  virtual void SetButton(TCivUnit* selectedOrder); // Mac: SetButton(TCivUnit*)
};
ASSERT_SIZE(TCivilianButton, 0xa0);
