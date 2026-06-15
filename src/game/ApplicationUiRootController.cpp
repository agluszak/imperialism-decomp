#include "game/ApplicationUiRootController.h"

#include "game/CPtrList.h"
#include "game/TView.h"
#include "game/ui_widget_thunks.h"
#include <new.h>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 WrapperFor_thunk_GetTickCountDiv16_At0048a410(void);

extern "C" CRuntimeClass PTR_s_TApplication_00648af8;

// FUNCTION: IMPERIALISM 0x00486680
void* __cdecl CreateTApplicationInstance(void) {
  ApplicationUiRootController* controller =
      reinterpret_cast<ApplicationUiRootController*>(AllocateWithFallbackHandler(0x48));
  if (controller == 0) {
    return 0;
  }
  new (controller) ApplicationUiRootController();
  return controller;
}

// vtable slot 0x00 (0x00486740 via ILT): return the TApplication RTTI name pointer.
// FUNCTION: IMPERIALISM 0x00486740
CRuntimeClass* ApplicationUiRootController::GetRuntimeClass() const {
  return &PTR_s_TApplication_00648af8;
}

// FUNCTION: IMPERIALISM 0x00486760
ApplicationUiRootController::ApplicationUiRootController()
    : TEventHandler(), activeView(0), screenModeAt24(0), field28(0), embeddedList() {
  g_pApplicationUiRootController = this;
}

// FUNCTION: IMPERIALISM 0x004867e0
ApplicationUiRootController::~ApplicationUiRootController() {
  g_pApplicationUiRootController = 0;
  for (void** cursor = reinterpret_cast<void**>(embeddedList.head); cursor != 0;
       cursor = reinterpret_cast<void**>(*cursor)) {
  }
  embeddedList.head = 0;
  embeddedList.field08 = 0;
  embeddedList.field0c = 0;
  embeddedList.field10 = 0;
  FreeLinkedBlockChain(reinterpret_cast<void*>(embeddedList.field14));
  embeddedList.field14 = 0;
}

// FUNCTION: IMPERIALISM 0x00486880
void ApplicationUiRootController::SetActiveView(TView* view) {
  this->activeView = view;
}

// FUNCTION: IMPERIALISM 0x004868a0
TView* ApplicationUiRootController::GetActiveView() {
  return this->activeView;
}

// vtable slot 0x25 placeholder (0x00486650 body deferred pending TCommandHandler class
// recovery; see header note). Real body calls the arg's vtable slots 0x0b (no-arg command
// processor, not yet modeled) and 0x07 (release/destroy).
void ApplicationUiRootController::vmethod_0037() {}

// vtable slot 0x28 (0x00486990 via ILT 0x00405551): original body is `RET 0xc` (takes
// three stack args, does nothing). A no-op hook for viewport-edge auto-scroll handling.
// FUNCTION: IMPERIALISM 0x00486990
void ApplicationUiRootController::HandleTurnEventViewportEdgeAutoScroll(int arg1, int arg2,
                                                                        int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// vtable slot 0x29 (0x004869b0): intrusive-list insert/remove on embeddedList. Each node
// is { void* next; void* prev; int data; } (12 bytes). When insertFlag is nonzero, pop a
// node from the free list (allocating and link-building a fresh 12-byte-per-entry block
// when the free list is empty), store `value` at node+8, and link the node at the list
// head. When zero, walk to the first node whose data matches `value`, unlink it, return
// it to the free list, and free the whole block chain if the list becomes empty.
// FUNCTION: IMPERIALISM 0x004869b0
void ApplicationUiRootController::InsertOrRemoveTrackedEntry(int value, char insertFlag) {
  if (insertFlag != 0) {
    int priorHead = reinterpret_cast<int>(embeddedList.head);
    if (embeddedList.field10 == 0) {
      int newBlock = reinterpret_cast<int>(AllocateAndLinkBlockHead(
          reinterpret_cast<void**>(&embeddedList.field14), embeddedList.blockSize, 0xc));
      int entryCount = embeddedList.blockSize;
      int* cursor = reinterpret_cast<int*>(newBlock + (entryCount * 0xc) - 8);
      for (entryCount = entryCount - 1; entryCount >= 0; entryCount = entryCount - 1) {
        *cursor = embeddedList.field10;
        embeddedList.field10 = reinterpret_cast<int>(cursor);
        cursor = cursor - 3;
      }
    }
    int* node = reinterpret_cast<int*>(embeddedList.field10);
    embeddedList.field10 = node[0];
    node[1] = 0;
    node[0] = priorHead;
    embeddedList.field0c = embeddedList.field0c + 1;
    node[2] = 0;
    node[2] = value;
    if (embeddedList.head == 0) {
      embeddedList.field08 = reinterpret_cast<int>(node);
      embeddedList.head = reinterpret_cast<void*>(node);
      return;
    }
    *reinterpret_cast<int**>(reinterpret_cast<int>(embeddedList.head) + 4) = node;
    embeddedList.head = reinterpret_cast<void*>(node);
    return;
  }
  int* match = reinterpret_cast<int*>(embeddedList.head);
  while (match != 0) {
    if (match[2] == value) {
      break;
    }
    match = reinterpret_cast<int*>(match[0]);
  }
  if (match != 0) {
    if (match == reinterpret_cast<int*>(embeddedList.head)) {
      embeddedList.head = reinterpret_cast<void*>(match[0]);
    } else {
      *reinterpret_cast<int*>(match[1]) = match[0];
    }
    if (match == reinterpret_cast<int*>(embeddedList.field08)) {
      embeddedList.field08 = match[1];
    } else {
      *reinterpret_cast<int*>(match[0] + 4) = match[1];
    }
    match[0] = embeddedList.field10;
    embeddedList.field10 = reinterpret_cast<int>(match);
    int newCount = embeddedList.field0c - 1;
    embeddedList.field0c = newCount;
    if (newCount == 0) {
      for (int* p = reinterpret_cast<int*>(embeddedList.head); p != 0;
           p = reinterpret_cast<int*>(p[0])) {
      }
      embeddedList.field0c = 0;
      embeddedList.field10 = 0;
      embeddedList.field08 = 0;
      embeddedList.head = 0;
      FreeLinkedBlockChain(reinterpret_cast<void*>(embeddedList.field14));
      embeddedList.field14 = 0;
    }
  }
}

// vtable slot 0x2a (0x00486b10 via ILT 0x00403f21): walk the embedded list from head,
// invoking the per-entry tick (receiver at node+8) with `arg` for each entry. The
// per-entry tick is a __thiscall on the node's data pointer (ECX = node[2]) with one
// stack arg; routed through the thunk in repo form (rule 9).
// FUNCTION: IMPERIALISM 0x00486b10
void ApplicationUiRootController::TickEachTrackedEntry(int arg) {
  int* node = reinterpret_cast<int*>(embeddedList.head);
  while (node != 0) {
    int* next = reinterpret_cast<int*>(node[0]);
    reinterpret_cast<void(__fastcall*)(int, int, int)>(reinterpret_cast<void (*)()>(
        WrapperFor_thunk_GetTickCountDiv16_At0048a410))(node[2], 0, arg);
    node = next;
  }
}
