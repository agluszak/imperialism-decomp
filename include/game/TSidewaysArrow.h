#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

// TEMP: recover TUpDownPictureButton as the real base before ctor/SYNTHETIC dtor work.
// VTABLE: IMPERIALISM 0x663540
class TSidewaysArrow : public TPictureButton {
public:
  int repeatDeadlineTick; // 0x94

  void HandleTradeArrowAutoRepeatTickAndDispatch(int repeatState, void* arg8, void* argC,
                                                 void* dispatchArg, void* arg14);
};

ASSERT_SIZE(TSidewaysArrow, 0x98);
