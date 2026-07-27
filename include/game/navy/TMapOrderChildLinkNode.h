#pragma once

#include "compat.h"

class TObject;
class TTaskForce;
class TShip;

// Custom 16-byte doubly-linked-list *cell* used for the map-order child chains
// (TTaskForce::shipList and TNavyMission::orderList24 /
// TScatteredShipsMission). This is a hand-rolled linked list, NOT an MFC CList:
//   * each cell is a separately heap-allocated 16-byte block (CreateLinkedOrder-
//     Node 0x552650 allocates one; 0x552590/0x5525d0/0x5526e0 free one);
//   * the owning object stores only a bare head pointer, not an embedded MFC
//     list object;
//   * field order is payload, next, prev, active byte;
//   * insertion and removal manually rewire the next/prev links;
//   * there is no CPlex, free-node list, block size, head/tail/count collection
//     state, or MFC POSITION API anywhere in the node methods.
//
// One shared node implementation. The out-of-line node methods live at single
// addresses and are called from BOTH the task-force and navy-mission chains
// (verified via xrefs), so there are no `TLinkNode<TTaskForce>` /
// `TLinkNode<TShip>` template specializations -- with this toolchain those would
// emit separate symbols/bodies. The stored payload is therefore the common base
// `TObject*` (TTaskForce derives `TObject` at offset 0 for shipList, TShip
// derives `TObject` at offset 0 for orderList24); semantic call sites downcast
// with `static_cast`, since the owning context determines the concrete type.
//
// Ownership: the cell does NOT own its payload. DeleteMapOrderChildLinkAndReturn-
// Next (0x552590) frees only the cell; navy-mission callers null `payload` before
// deleting the cell; PruneDefeated (0x5526e0) frees the payload SEPARATELY via a
// virtual `payload->Free()`, then frees the cell. So node deletion never deletes
// the payload on its own.
class TMapOrderChildLinkNode {
public:
  TObject* payload;             // +0x00 (TTaskForce* for shipList, TShip* for orderList24)
  TMapOrderChildLinkNode* next; // +0x04
  TMapOrderChildLinkNode* prev; // +0x08
  unsigned char active;         // +0x0c
  unsigned char pad_0d;
  unsigned char pad_0e;
  unsigned char pad_0f;

  // Trivial default ctor for the POD link cell: GetOrCreateTaskForceOrderNodeBy-
  // Template's raw `new` (0x553bc0) does no field writes before the caller's own
  // stores. It exists only because the chain-insert ctor below suppresses the
  // implicit one; no original function address corresponds to it (never emitted
  // out of line).
  // NOOP: verified empty in original 0x00553c25 (the new-expression proceeds
  // directly from allocation cleanup to the caller's field stores, with no ctor call)
  TMapOrderChildLinkNode() {}

  // Fills the cell and splices it between two existing cells, marking it active.
  // Either neighbour may be null. 0x005524d0, __thiscall.
  void InitAndLinkBetween(TObject* child, TMapOrderChildLinkNode* prevNode,
                          TMapOrderChildLinkNode* nextNode);
  // Unlinks this cell from wherever it currently sits, then splices it between the
  // two given cells. Either may be null. 0x00552540, __thiscall.
  void RelinkBetween(TMapOrderChildLinkNode* prevNode, TMapOrderChildLinkNode* nextNode);
  // Inline head-insert constructor: chains the new cell in front of `nextNode`
  // (which may be null). CreateLinkedOrderNode's 0x552650 body is exactly the
  // `new`-site expansion of this ctor under /Ob1: alloc null-guard, these
  // assignments in this order, then the two relinks. The pad bytes stay
  // uninitialized, matching the original stores.
  TMapOrderChildLinkNode(TObject* child, TMapOrderChildLinkNode* nextNode) {
    next = nextNode;
    payload = child;
    prev = 0;
    active = 1;
    if (nextNode != 0) {
      nextNode->prev = this;
    }
    if (prev != 0) {
      prev->next = this;
    }
  }

  // Real __thiscall method (0x552510, ECX=this cell, one stack arg, RET 4).
  // Null-safe on `this`; walks `this` and its `next` chain for the first cell
  // whose `payload` == `child`. Only compares the payload pointer -- never
  // dereferences it -- so `child` is the common base `TObject*`.
  TMapOrderChildLinkNode* FindNodeMatching(TObject* child); // 0x552510

  // Real __thiscall method (0x536f70, ECX=this cell, one stack arg, RET 4).
  // Null-safe on `this`; sets `active` on `this` and every following cell in the
  // `next` chain. Pure cell operation; the payload is untouched.
  void SetChainActiveFlag(unsigned char flag); // 0x536f70

  // Unlinks `this` from its siblings, frees ONLY the cell, and returns the old
  // `next`. Does not touch the payload. 0x552590.
  TMapOrderChildLinkNode* DeleteMapOrderChildLinkAndReturnNext();
  // Null-safe on `this`; unlinks and frees the first cell in the chain whose
  // `payload` == `child` (recursing down `next`); frees only the cell. Returns
  // the cell now standing where `this` stood (0 on null, the old `next` when
  // `this` itself was removed, otherwise `this`); every current caller ignores
  // it. Only compares the payload pointer, so `child` is `TObject*`. 0x5525d0.
  TMapOrderChildLinkNode* RemoveLinkedOrderNodeByValueRecursive(TObject* child);
  // Receiver is the NEW cell's `next` (may be null): heap-allocates a fresh
  // 16-byte cell for `child`, chained in front of `this`, and returns it. Only
  // stores the payload pointer, so `child` is `TObject*`. 0x552650.
  TMapOrderChildLinkNode* CreateLinkedOrderNode(TObject* child);
  // Null-safe on `this`; frees leading defeated children off the chain (each
  // payload's short at +0x1c <= 0), recursively prunes the survivors' tail, and
  // returns the new head. This is the one method that dereferences the payload:
  // it is only ever called on shipList (TTaskForce payloads -- see the
  // TShip caller 0x5509c0, which prunes owner->shipList), so it reads the
  // payload as TTaskForce and calls the payload's virtual Free() (TObject slot
  // 7) before freeing the cell. 0x5526e0.
  TMapOrderChildLinkNode* PruneDefeatedMapOrderChildrenAndReturnHead();
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);
