#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;
int AllocateWithFallbackHandler(undefined4 size_bytes);

struct TTextListItem {
  char text[64];
};

// VTABLE: IMPERIALISM 0x00644778
class TTextList : public TView {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  TTextListItem items[64];
  int totalItems;
  int scrollOffset;
  int selectedIndex;
  short itemHeight;
  char padding_106e[2];

  TTextList() : TView() {
    itemHeight = 0x10;
    totalItems = 0;
    scrollOffset = 0;
    selectedIndex = -1;
  }
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  static TTextList* CreateTTextListInstance();

  void ApplyRectSlot110(RECT* rectBuffer) override;
  void BeginMouseCaptureAndStartRepeatTimer(Point32* point, int arg2, int arg3, int arg4) override;
};

ASSERT_SIZE(TTextList, 0x1070);
