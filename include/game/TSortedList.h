#pragma once

#include "game/TPtrList.h"

struct TSortedList : public TPtrList {
  static TSortedList* CreateTSortedListInstance();
  static void* GetTSortedListClassNamePointer();
};

typedef char TSortedListSizeMustMatch[(sizeof(TSortedList) == 0x20) ? 1 : -1];
