#pragma once

#include "decomp_types.h"

struct ObjectPoolListNode {
  int object_ptr;
  ObjectPoolListNode *next;
  int prev_node_ptr;
  unsigned char active_flag;
  unsigned char pad_0d;
  unsigned char pad_0e;
  unsigned char pad_0f;
};

struct ObjectPoolOwner {
  char pad_00[0x10];
  ObjectPoolListNode *head;
  int active_node;
  char bucket_counts_base[0x100];
};

ObjectPoolListNode *FindMissionOrderNodeById(ObjectPoolListNode *node, int child_node_id);
ObjectPoolListNode * __fastcall DeleteMapOrderChildLinkAndReturnNext(
    ObjectPoolListNode *child_link_node);
void __cdecl RemoveLinkedOrderNodeByValueRecursive(
    ObjectPoolListNode *node, int child_node_id);
ObjectPoolListNode *CreateLinkedOrderNode(
    ObjectPoolListNode *next_node, int child_node_id);
ObjectPoolListNode * __fastcall PruneDefeatedMapOrderChildrenAndReturnHead(
    ObjectPoolListNode *child_link_head);
void __cdecl NoOpTaskForceVtableSlot(void);
void RelinkMapOrderQueueNodeBetween(void *node_this, int prev_node, int next_node);

class ObjectPool {
public:
  char pad_00[0x04];
  s16 order_type;
  char pad_06[0x06];
  ObjectPoolOwner *owner;

  void RemoveNode(int self);
};
