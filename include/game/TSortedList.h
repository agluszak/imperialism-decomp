#pragma once

#include "compat.h"
#include "game/TPtrList.h"

// Sorted game list leaf sharing the TPtrList storage layout. Mac CodeWarrior
// names this as TSortedList, but Windows vtable membership is grounded by the
// constructor write to 0x00648ee0.
// VTABLE: IMPERIALISM 0x00648ee0
struct TSortedList : public TPtrList {
  CRuntimeClass* GetRuntimeClass() const override;
  TSortedList(); // 0x004a8640: sets vptr + constructs the embedded CPtrList (block size 10)

  static TSortedList* CreateTSortedListInstance();
};

ASSERT_SIZE(TSortedList, 0x20);
