#pragma once

#include "game/mfc.h"
#include "game/global_data_tables.h"

// The McAppUI live-view registry: every TWindow/TView links itself in on construction
// (inline AddHead) and unlinks on teardown. An MFC CPtrList, base 0x006a1a40
// (vtable 0x0064b580). Iterated through CWMgrIterator below.
// g_LiveViewRegistry — see game/global_data_tables.h.

// MacApp's window-manager iterator (CIterator-derived): a 12-byte stack cursor that
// sweeps every live UI window/view in g_LiveViewRegistry (e.g.
// TDisplayMgr::DispatchUiWindowStatusTickForClass99Windows). Reset() arms it,
// FirstWindow()/NextWindow() walk the registry, More() reports whether the current node
// still holds an entry. Identified via the Mac CodeWarrior symbol oracle (the framework
// is MacApp-derived: TView/TWindow/CWMgrIterator).
class CWMgrIterator {
public:
  void Reset(unsigned char fForward); // 0x004923f0
  void* FirstWindow();                // 0x00492440
  void* NextWindow();                 // 0x00492470
  int More();                         // 0x004924a0

  POSITION nextPosition; // +0x00 — next registry node to visit
  int fForward;          // +0x04 — iteration-direction flag captured by Reset
  void* current;         // +0x08 — current live view (null once past the end)
};

// 0x4924c0: pops the singly-linked list head (*head advances to next) and returns the
// popped node payload (node + 8 bytes).
int __stdcall PopSinglyLinkedListHeadPointer(int* head);
