#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class TMapOrderEntry;

// Child-link node for map-order mission trees (NOT TOcean / TZone).
struct TMapOrderChildLinkNode {
  TMapOrderEntry* object_ptr;
  TMapOrderChildLinkNode* next;
  TMapOrderChildLinkNode* prev_link;
  unsigned char active_flag;
  unsigned char pad_0d;
  unsigned char pad_0e;
  unsigned char pad_0f;
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);

// Per-owner bucket table for active map-order entries (Ghidra: ObjectPoolOwner).
struct TMapOrderEntryOwnerContext {
  char pad_00[0x10];
  TMapOrderChildLinkNode* head;
  TMapOrderEntry* active_node;
  char bucket_counts_base[0x100];
};

// Map-order queue entry (0x34 bytes). Ghidra mislabels this slice as "ObjectPool";
// it is unrelated to TObject or keyboard/map-action InputState.
class TMapOrderEntry {
public:
  int field_00;
  s16 order_type;
  s16 order_strength;
  int attachment;
  TMapOrderEntryOwnerContext* owner;
  char pad_10[0x0c];
  s16 required_count;
  char pad_1e[0x02];
  int attached_entity;
  char pad_24[0x04];
  TMapOrderEntry* queue_prev;
  TMapOrderEntry* queue_next;
  s16 tiebreak_strength;
  char pad_32[0x02];

  static TMapOrderChildLinkNode* FindMissionOrderNodeById(TMapOrderChildLinkNode* node,
                                                          TMapOrderEntry* child_node);
  static TMapOrderChildLinkNode*
  DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node);
  static void RemoveLinkedOrderNodeByValueRecursive(TMapOrderChildLinkNode* node,
                                                    TMapOrderEntry* child_node);
  static TMapOrderChildLinkNode* CreateLinkedOrderNode(TMapOrderChildLinkNode* next_node,
                                                       TMapOrderEntry* child_node);
  static TMapOrderChildLinkNode*
  PruneDefeatedMapOrderChildrenAndReturnHead(TMapOrderChildLinkNode* child_link_head);

  void RelinkMapOrderQueueNodeBetween(TMapOrderEntry* prev_node, TMapOrderEntry* next_node);
  void DecrementRequiredCount(short decrement);
  TMapOrderEntry* SelectPreferredMapOrderEntryByPriorityRules(TMapOrderEntry* candidate,
                                                             int compareAttachedFlag);
  void RemoveNode(int self);
};

ASSERT_SIZE(TMapOrderEntry, 0x34);
