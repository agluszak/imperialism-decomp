#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/MfcRuntime.h"

struct ObjectPoolListNode {
  int object_ptr;
  ObjectPoolListNode* next;
  int prev_node_ptr;
  unsigned char active_flag;
  unsigned char pad_0d;
  unsigned char pad_0e;
  unsigned char pad_0f;
};

struct ObjectPoolOwner {
  char pad_00[0x10];
  ObjectPoolListNode* head;
  int active_node;
  char bucket_counts_base[0x100];
};

// Map-order queue entry (Ghidra mislabels this slice as ObjectPool).
class TMapOrderEntry {
public:
  int field_00;
  s16 order_type;
  s16 order_strength;
  int attachment;
  ObjectPoolOwner* owner;
  char pad_10[0x0c];
  s16 required_count;
  char pad_1e[0x02];
  int attached_entity;
  char pad_24[0x04];
  TMapOrderEntry* queue_prev;
  TMapOrderEntry* queue_next;
  s16 tiebreak_strength;
  char pad_32[0x02];

  static ObjectPoolListNode* FindMissionOrderNodeById(ObjectPoolListNode* node, int child_node_id);
  static ObjectPoolListNode* DeleteMapOrderChildLinkAndReturnNext(
      ObjectPoolListNode* child_link_node);
  static void RemoveLinkedOrderNodeByValueRecursive(ObjectPoolListNode* node, int child_node_id);
  static ObjectPoolListNode* CreateLinkedOrderNode(ObjectPoolListNode* next_node, int child_node_id);
  static ObjectPoolListNode* PruneDefeatedMapOrderChildrenAndReturnHead(
      ObjectPoolListNode* child_link_head);

  void RelinkMapOrderQueueNodeBetween(TMapOrderEntry* prev_node, TMapOrderEntry* next_node);
  void DecrementRequiredCount(short decrement);
  int SelectPreferredMapOrderEntryByPriorityRules(TMapOrderEntry* candidate, int compareAttachedFlag);
  void RemoveNode(int self);
};

// TEMP: Ghidra name until call sites are renamed.
typedef TMapOrderEntry ObjectPool;

ASSERT_SIZE(TMapOrderEntry, 0x34);
