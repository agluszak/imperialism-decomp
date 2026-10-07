#pragma once

#include "compat.h"
#include "game/ui_screens/TPictureButton.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x65eb60
class T2PictureButton : public TPictureButton {
public:
  virtual void SetAvailability(char isAvailable, char refreshNow);
  T2PictureButton();
  virtual ~T2PictureButton() override;
  DECLARE_DYNCREATE(T2PictureButton)
};

ASSERT_SIZE(T2PictureButton, 0x94);
