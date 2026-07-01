#include "game/TMapOrderEntry.h"
#include "game/global_data_tables.h"

namespace {

typedef void(__cdecl* DestroyOrderNodeFn)(void*);

class TaskForceOrderVirtual {
public:
  virtual void Slot00(void);
  virtual void Slot04(void);
  virtual void Slot08(void);
  virtual void Slot0C(void);
  virtual void Slot10(void);
  virtual void Slot14(void);
  virtual void Slot18(void);
  virtual void Slot1C(void);

protected:
  ~TaskForceOrderVirtual() {}
};

} // namespace

// FUNCTION: IMPERIALISM 0x00550670
TMapOrderEntry*
TMapOrderEntry::SelectPreferredMapOrderEntryByPriorityRules(TMapOrderEntry* candidate,
                                                            int compareAttachedFlag) {
  if ((char)compareAttachedFlag != '\0') {
    if (attachment != 0) {
      return candidate;
    }
    if (candidate == 0) {
      return this;
    }
    if (candidate->attached_entity != 0) {
      return this;
    }
  }
  if (candidate == 0) {
    return this;
  }
  if (this != 0) {
    int selfAttachment = attachment;
    int candidateAttachment = candidate->attached_entity;
    bool preferSelf = false;
    if (selfAttachment == 0) {
      preferSelf = false;
    } else if (candidateAttachment == 0) {
      preferSelf = true;
    } else {
      preferSelf = *reinterpret_cast<short*>(candidateAttachment + 0x10) <
                   *reinterpret_cast<short*>(selfAttachment + 0x10);
    }
    if (preferSelf) {
      return this;
    }

    bool preferCandidate = false;
    if (candidateAttachment == 0) {
      preferCandidate = false;
    } else if (selfAttachment == 0) {
      preferCandidate = true;
    } else {
      preferCandidate = *reinterpret_cast<short*>(selfAttachment + 0x10) <
                        *reinterpret_cast<short*>(candidateAttachment + 0x10);
    }
    if (!preferCandidate) {
      if (order_type != candidate->order_type) {
        if (candidate->order_type <= order_type) {
          return this;
        }
        return candidate;
      }
      short selfBucket =
          (order_strength / 100 + (order_strength >> 15)) -
          static_cast<short>(
              (static_cast<__int64>(static_cast<int>(order_strength)) * 0x51eb851f) >> 63);
      short candidateBucket =
          (candidate->tiebreak_strength / 100 + (candidate->tiebreak_strength >> 15)) -
          static_cast<short>(
              (static_cast<__int64>(static_cast<int>(candidate->tiebreak_strength)) * 0x51eb851f) >>
              63);
      if (selfBucket != candidateBucket) {
        if (candidateBucket <= selfBucket) {
          return this;
        }
        return candidate;
      }
      if (candidate->required_count < required_count) {
        return this;
      }
    }
  }
  return candidate;
}

// FUNCTION: IMPERIALISM 0x00550f80
void TMapOrderEntry::DecrementRequiredCount(short decrement) {
  required_count = static_cast<s16>(required_count - decrement);
}

// FUNCTION: IMPERIALISM 0x00550ff0
void TMapOrderEntry::RemoveNode(int self) {
  TMapOrderEntryOwnerContext* owner_ctx = owner;
  if (owner_ctx != 0) {
    TMapOrderChildLinkNode* list_head = owner_ctx->head;

    if ((list_head != 0) && (this != list_head->object_ptr)) {
      list_head = FindMissionOrderNodeById(list_head->next, this);
    }

    if (list_head != 0) {
      list_head = owner_ctx->head;
      if (list_head != 0) {
        if (this == list_head->object_ptr) {
          list_head = DeleteMapOrderChildLinkAndReturnNext(list_head);
        } else {
          RemoveLinkedOrderNodeByValueRecursive(list_head->next, this);
        }
      }

      owner_ctx->head = list_head;

      // Low 16 bits of the shared per-order-type descriptor's enabled-flag
      // dword (see TNavyOrderResourceDescriptor in global_data_tables.h),
      // reused here as a bucket-count array index.
      short bucket_offset = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[order_type].enabledFlagOrBucketOffset);
      short* bucket_counter =
          reinterpret_cast<short*>(reinterpret_cast<char*>(owner_ctx) + 0x18 + bucket_offset * 2);
      *bucket_counter = *bucket_counter - 1;
    }

    if (this == owner_ctx->active_node) {
      list_head = owner_ctx->head;
      owner_ctx->active_node = 0;
      for (; list_head != 0; list_head = list_head->next) {
        owner_ctx->active_node = list_head->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(
            owner_ctx->active_node, 0);
      }
    }

    owner = 0;
  }

  if (self != 0) {
    DestroyOrderNodeFn destroy_node =
        reinterpret_cast<DestroyOrderNodeFn>(static_cast<unsigned int>(0x00553bc0));
    destroy_node(this);
  }
}

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TMapOrderEntry::FindMissionOrderNodeById(TMapOrderChildLinkNode* node,
                                                                 TMapOrderEntry* child_node) {
  while (node != 0) {
    if (node->object_ptr == child_node) {
      return node;
    }
    node = node->next;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00552590
TMapOrderChildLinkNode*
TMapOrderEntry::DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node) {
  TMapOrderChildLinkNode* next_node = child_link_node->next;
  if (next_node != 0) {
    next_node->prev_link = child_link_node->prev_link;
  }
  if (child_link_node->prev_link != 0) {
    child_link_node->prev_link->next = child_link_node->next;
  }

  delete child_link_node;
  return next_node;
}

// FUNCTION: IMPERIALISM 0x005525d0
void TMapOrderEntry::RemoveLinkedOrderNodeByValueRecursive(TMapOrderChildLinkNode* node,
                                                           TMapOrderEntry* child_node) {
  if (node == 0) {
    return;
  }

  if (node->object_ptr == child_node) {
    if (node->next != 0) {
      node->next->prev_link = node->prev_link;
    }
    if (node->prev_link != 0) {
      node->prev_link->next = node->next;
    }
    delete node;
    return;
  }

  RemoveLinkedOrderNodeByValueRecursive(node->next, child_node);
}

// FUNCTION: IMPERIALISM 0x00552650
TMapOrderChildLinkNode* TMapOrderEntry::CreateLinkedOrderNode(TMapOrderChildLinkNode* next_node,
                                                              TMapOrderEntry* child_node) {
  TMapOrderChildLinkNode* new_node = new TMapOrderChildLinkNode();
  if (new_node == 0) {
    return 0;
  }

  new_node->object_ptr = child_node;
  new_node->next = next_node;
  new_node->prev_link = 0;
  new_node->active_flag = 1;
  new_node->pad_0d = 0;
  new_node->pad_0e = 0;
  new_node->pad_0f = 0;

  if (next_node != 0) {
    next_node->prev_link = new_node;
  }
  if (new_node->prev_link != 0) {
    new_node->prev_link->next = new_node;
  }
  return new_node;
}

// FUNCTION: IMPERIALISM 0x005526e0
TMapOrderChildLinkNode* TMapOrderEntry::PruneDefeatedMapOrderChildrenAndReturnHead(
    TMapOrderChildLinkNode* child_link_head) {
  while (true) {
    if (child_link_head == 0) {
      return 0;
    }

    TMapOrderEntry* child_node = child_link_head->object_ptr;
    if (0 < child_node->required_count) {
      break;
    }

    child_node->owner = 0;
    reinterpret_cast<TaskForceOrderVirtual*>(child_node)->Slot1C();
    child_link_head = DeleteMapOrderChildLinkAndReturnNext(child_link_head);
  }

  PruneDefeatedMapOrderChildrenAndReturnHead(child_link_head->next);
  return child_link_head;
}

// FUNCTION: IMPERIALISM 0x005528c0
void __cdecl NoOpTaskForceVtableSlot(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005528e0
void TMapOrderEntry::RelinkMapOrderQueueNodeBetween(TMapOrderEntry* prev_node,
                                                    TMapOrderEntry* next_node) {
  TMapOrderEntry* old_prev_node = queue_prev;
  TMapOrderEntry* old_next_node = queue_next;

  if (old_prev_node != 0) {
    old_prev_node->queue_next = old_next_node;
  }
  if (old_next_node != 0) {
    old_next_node->queue_prev = old_prev_node;
  }

  queue_prev = prev_node;
  queue_next = next_node;

  if (prev_node != 0) {
    prev_node->queue_next = this;
  }
  if (queue_next != 0) {
    queue_next->queue_prev = this;
  }
}
