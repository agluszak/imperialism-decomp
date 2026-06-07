#pragma once

#include "compat.h"
#include "game/TView.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTTextList;

struct TTextListItem {
  char text[64];
};

// VTABLE: IMPERIALISM 0x00644778
class TTextList : public TView {
public:
  TTextListItem items[64];
  int totalItems;
  int scrollOffset;
  int selectedIndex;
  short itemHeight;
  char padding_106e[2];

  TTextList() {
    this->TView::thunk_ConstructUiResourceEntryBase();
    *reinterpret_cast<void**>(this) = &g_vtblTTextList;
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
  static void* GetTTextListClassNamePointer();

  void RenderTextListRowsWithSelectionHighlight();
  void HandleTextListScrollSelectionChange(int* pScrollData);
};

ASSERT_SIZE(TTextList, 0x1070);
