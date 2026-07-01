#pragma once

#include "game/mfc.h"

class TView;

// Focus-animation helper object
// completion callback at slot 0x14 (index 5).
// VTABLE: IMPERIALISM (provisional)
class TFocusAnimation : public CObject {
public:
#define TFOCUS_ANIMATION_DUMMY(n) virtual void TFocusAnimationDummy##n() = 0
  TFOCUS_ANIMATION_DUMMY(00);
  TFOCUS_ANIMATION_DUMMY(01);
  TFOCUS_ANIMATION_DUMMY(02);
  TFOCUS_ANIMATION_DUMMY(03);
  TFOCUS_ANIMATION_DUMMY(04);
#undef TFOCUS_ANIMATION_DUMMY

  virtual void DispatchCompletionRecordSlot14(int* completionRecord); // 0x14

  TView* scopedRenderTarget; // 0x04 — render-target view for the scoped QuickDraw context
  short currentFrame;         // 0x08
  short frameCount;           // 0x0a
  short field0c;              // 0x0c
  char pad_0e[2];
  int frameTick;      // 0x10
  int frameTickLimit; // 0x14
  int field18;        // 0x18
  int field1c;        // 0x1c
  int field20;        // 0x20
  int field24;        // 0x24
  int field28;        // 0x28
  char enabledFlag;   // 0x2c

  void DestructTFocusAnimationAndMaybeFree();
};
