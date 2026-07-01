#pragma once

#include "game/TAnimation.h"

// Focus-animation helper object
// completion callback at slot 0x14 (index 5 of subclass, slot 13 in vtable).
// VTABLE: IMPERIALISM 0x0064c268
class TFocusAnimation : public TAnimation {
  DECLARE_DYNCREATE(TFocusAnimation)
public:
  TFocusAnimation();
  virtual undefined WrapperFor_InvalidateCityDialogRectRegion_At0049f140() override; // slot 10 / 0x28
  virtual void VTableSlot0D(int* completionRecord = nullptr); // slot 13 / 0x34
  virtual void Helper_Uses_BlitRectWithOptionalTransparency_At004a0280(); // slot 14 / 0x38


  void*& ScopedRenderTarget() { return *reinterpret_cast<void**>(&field04); }
  short& Field08() { return *reinterpret_cast<short*>(&bitmapRect.left); }
  short& Field0a() { return *(reinterpret_cast<short*>(&bitmapRect.left) + 1); }
  short& Field0c() { return *reinterpret_cast<short*>(&bitmapRect.top); }
  LONG& FrameTick() { return bitmapRect.right; }
  LONG& FrameTickLimit() { return bitmapRect.bottom; }
  int& Field18() { return *reinterpret_cast<int*>(&bitmapResource); }
  int& SourceLeft() { return *reinterpret_cast<int*>(&field1e[0]); }
  int& SourceTop() { return *reinterpret_cast<int*>(&field1e[4]); }
  int& SourceRight() { return *reinterpret_cast<int*>(&field1e[8]); }
  int& SourceBottom() { return *reinterpret_cast<int*>(&field1e[12]); }

  char enabledFlag;   // 0x2c

  char pad_2d[3];

  void DestructTFocusAnimationAndMaybeFree();
};

