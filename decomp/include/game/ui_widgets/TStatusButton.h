#pragma once

#include "compat.h"

#include "game/TButton.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x664f68
class TStatusButton : public TButton {
public:
  // FUNCTION: IMPERIALISM 0x005863e0
  ~TStatusButton() override {}
  TStatusButton();
  DECLARE_DYNCREATE(TStatusButton)
  void DoEvent(int selectedIndex, TEventHandler* sourceHandler, TEvent* event) override;
};
ASSERT_SIZE(TStatusButton, 0x84);
