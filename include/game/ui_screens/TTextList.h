#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"

struct CRuntimeClass;

struct TTextListItem {
  char text[64];
};

// VTABLE: IMPERIALISM 0x00644778
class TTextList : public TView {
public:
  // FUNCTION: IMPERIALISM 0x0045af60
  ~TTextList() override {}
  DECLARE_DYNCREATE(TTextList)
  TTextListItem items[64];
  int totalItems;
  int scrollOffset;
  int selectedIndex;
  short itemHeight;
  char padding_106e[2];

  TTextList();

  void AddEntry(char* entryText); // 0x57ac50

  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
};

ASSERT_SIZE(TTextList, 0x1070);
