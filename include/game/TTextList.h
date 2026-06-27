#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;

struct TTextListItem {
  char text[64];
};

// VTABLE: IMPERIALISM 0x00644778
class TTextList : public TView {
public:
  DECLARE_DYNCREATE(TTextList)
  TTextListItem items[64];
  int totalItems;
  int scrollOffset;
  int selectedIndex;
  short itemHeight;
  char padding_106e[2];

  TTextList();

  static TTextList* CreateTTextListInstance();

  void ApplyRectSlot110(RECT* rectBuffer) override;
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) override;
};

ASSERT_SIZE(TTextList, 0x1070);
