#pragma once

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
  char pad_00[0x04];
  s16 order_type;
  char pad_06[0x06];
  ObjectPoolOwner* owner;

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
