#include "game/ui_core/TUiEvent.h"
// FUNCTION: IMPERIALISM 0x00483ab0
TUiEvent::~TUiEvent() {}

// SYNTHETIC: IMPERIALISM 0x00483ad0
// TUiEvent::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004845a0
TUiEvent::TUiEvent() : TEvent() {}

// Pops the head node off a singly-linked cell (advancing the cell to node->next) and returns
// the node's data slot (node+8). Same shape as PopSinglyLinkedListHeadPointer (0x4924c0).
// FUNCTION: IMPERIALISM 0x004845f0
int __stdcall DereferencePointerCellInPlace(int* head) {
  int* node = reinterpret_cast<int*>(*head);
  *head = *node;
  return reinterpret_cast<int>(node + 2);
}
