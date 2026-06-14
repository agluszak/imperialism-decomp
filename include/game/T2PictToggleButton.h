#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

// VTABLE: IMPERIALISM 0x664470
struct CRuntimeClass;
class T2PictToggleButton : public TToggleButton {
public:
  T2PictToggleButton();
  virtual ~T2PictToggleButton() override;
  CRuntimeClass* GetRuntimeClass() override;

  virtual void IsField3cWithinShortLimit84();
  virtual void SyncField0fTowardsField21ByDirectionAndRefresh(char direction);
};

ASSERT_SIZE(T2PictToggleButton, 0x90);
