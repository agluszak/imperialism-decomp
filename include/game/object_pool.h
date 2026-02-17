#pragma once

#include "decomp_types.h"

struct ObjectPoolListNode {
  int object_ptr;
  ObjectPoolListNode *next;
  int prev_node_ptr;
};

struct ObjectPoolOwner {
  char pad_00[0x10];
  ObjectPoolListNode *head;
  int active_node;
  char bucket_counts_base[0x100];
};

class ObjectPool {
public:
  char pad_00[0x04];
  s16 order_type;
  char pad_06[0x06];
  ObjectPoolOwner *owner;

  void RemoveNode(int self);
};
