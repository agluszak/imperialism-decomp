#include "game/TTaskForce.h"

#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00550670
TTaskForce* TTaskForce::SelectPreferredMapOrderEntryByPriorityRules(TTaskForce* candidate,
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
void TTaskForce::DecrementRequiredCount(short decrement) {
  required_count = static_cast<s16>(required_count - decrement);
}

// FUNCTION: IMPERIALISM 0x00550ff0
void TTaskForce::RemoveNode(int self) {
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
    // `self` is the RemoveNode caller's own owner-context pointer punned to
    // int (same pun this class already uses for `owner`/`contextAnchor`; see
    // TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink for the register
    // evidence that the real callee is __thiscall on that receiver).
    reinterpret_cast<TMapOrderEntryOwnerContext*>(self)->FindOrCreateChildOrderLink(this);
  }
}

// FUNCTION: IMPERIALISM 0x00551220
void TTaskForce::SetMapOrderActiveChildEntry(TTaskForce* newEntry) {
  owner = reinterpret_cast<TMapOrderEntryOwnerContext*>(newEntry);
  if (newEntry == nullptr) {
    return;
  }
  // TODO: promote body -- 0x55122f-0x551257 (only reached with a non-null
  // newEntry, which none of the bd 1uj.16 target-cluster callers exercise);
  // see bd 1uj.16 follow-up notes.
  newEntry->AssertValid();
}

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TTaskForce::FindMissionOrderNodeById(TMapOrderChildLinkNode* node,
                                                             TTaskForce* child_node) {
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
TTaskForce::DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node) {
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
void TTaskForce::RemoveLinkedOrderNodeByValueRecursive(TMapOrderChildLinkNode* node,
                                                       TTaskForce* child_node) {
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
TMapOrderChildLinkNode* TTaskForce::CreateLinkedOrderNode(TMapOrderChildLinkNode* next_node,
                                                          TTaskForce* child_node) {
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
TMapOrderChildLinkNode*
TTaskForce::PruneDefeatedMapOrderChildrenAndReturnHead(TMapOrderChildLinkNode* child_link_head) {
  while (true) {
    if (child_link_head == 0) {
      return 0;
    }

    TTaskForce* child_node = child_link_head->object_ptr;
    if (0 < child_node->required_count) {
      break;
    }

    child_node->owner = 0;
    child_node->Free();
    child_link_head = DeleteMapOrderChildLinkAndReturnNext(child_link_head);
  }

  PruneDefeatedMapOrderChildrenAndReturnHead(child_link_head->next);
  return child_link_head;
}

// SYNTHETIC: IMPERIALISM 0x00552770
// TTaskForce::CreateObject

// SYNTHETIC: IMPERIALISM 0x005527e0
// TTaskForce::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTaskForce, TObject)

TTaskForce::TTaskForce()
    : order_type(0), order_strength(0), attachment(0), owner(nullptr), childOrderList(nullptr),
      activeChildEntry(nullptr), contextAnchor(0), required_count(0), attached_entity(0),
      queue_prev(nullptr), queue_next(nullptr), tiebreak_strength(0) {}

TTaskForce::~TTaskForce() {}

void TTaskForce::WriteTo(TStream* stream) {
  (void)stream;
}

void TTaskForce::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005528c0
void __cdecl NoOpTaskForceVtableSlot(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005528e0
void TTaskForce::RelinkMapOrderQueueNodeBetween(TTaskForce* prev_node, TTaskForce* next_node) {
  TTaskForce* old_prev_node = queue_prev;
  TTaskForce* old_next_node = queue_next;

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

// FUNCTION: IMPERIALISM 0x00552930
void TTaskForce::Free() {
  while (childOrderList != nullptr) {
    childOrderList->object_ptr->owner = nullptr;

    TMapOrderChildLinkNode* next = childOrderList->next;
    if (next != nullptr) {
      next->prev_link = childOrderList->prev_link;
    }
    if (childOrderList->prev_link != nullptr) {
      childOrderList->prev_link->next = next;
    }
    delete childOrderList;
    childOrderList = next;
  }

  // Unlink from the global task-force queue (g_pNavyOrderManager->orderListHead04).
  if (g_pNavyOrderManager->orderListHead04 == this) {
    g_pNavyOrderManager->orderListHead04 = queue_next;
  }
  if (queue_prev != nullptr) {
    queue_prev->queue_next = queue_next;
  }
  if (queue_next != nullptr) {
    queue_next->queue_prev = queue_prev;
  }
  queue_prev = nullptr;
  queue_next = nullptr;

  // TODO: promote body -- 0x5529a8-0x552a18 notifies g_pActiveMapOrderContext
  // (TOcean) and then walks a CObList/CPtrList of observers keyed by an
  // unrecovered global array indexed by required_count (IsKindOf-gated
  // dispatch through a vtable slot 0x90 call); not yet recovered, see bd
  // 1uj.16 follow-up notes.

  delete this;
}

// FUNCTION: IMPERIALISM 0x00552f80
void TTaskForce::SetMapOrderType9AndQueue() {
  attachment = 9;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active_flag != 0) {
      node = node->next;
      continue;
    }

    TTaskForce* child = node->object_ptr;
    child->owner = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->order_type].enabledFlagOrBucketOffset);
    short* bucketCounter =
        reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev_link = node->prev_link;
    }
    if (node->prev_link != nullptr) {
      node->prev_link->next = next;
    }
    delete node;
    node = next;
  }

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  // MSVC500 keeps `for`-loop control variables in function scope, so this
  // reuses `node`'s declaration slot rather than shadowing/redeclaring it
  // with a new type -- a fresh TTaskForce* variable is used here instead.
  TTaskForce* head = g_pNavyOrderManager->orderListHead04;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->queue_next) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (node = childOrderList; node != nullptr; node = node->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (queue_prev != nullptr) {
      queue_prev->queue_next = queue_next;
    }
    if (queue_next != nullptr) {
      queue_next->queue_prev = queue_prev;
    }
    queue_prev = nullptr;
    queue_next = head;
    if (head != nullptr) {
      head->queue_prev = this;
    }
    g_pNavyOrderManager->orderListHead04 = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// FUNCTION: IMPERIALISM 0x005533f0
void TTaskForce::PromoteMapOrderChainAndQueue(void* pContextAnchor) {
  // TODO: promote body -- 0x553403's opening call (thunk 0x4081cf) on
  // pContextAnchor is not yet recovered; see bd 1uj.16 follow-up notes.
  (void)pContextAnchor;

  // Minimum g_NavyOrderResourceDescriptorTable[order_type].descriptorWeight
  // among *active* (active_flag != 0) children, clamped to the 10000
  // sentinel (no active children).
  int minPriority = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0) {
      short priority =
          g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
  }

  owner = reinterpret_cast<TMapOrderEntryOwnerContext*>(contextAnchor);

  int iterationBudget = (minPriority < 10000) ? minPriority : 0;
  if (iterationBudget > 0) {
    // TODO: promote body -- 0x55345f-0x553590's candidate-promotion loop
    // over `owner`'s still-uncharted growable-array region (data/capacity/
    // count at +0x28/+0x2c/+0x30, compared via a short field at +0x44); see
    // the TMapOrderEntryOwnerContext note in TTaskForce.h and bd 1uj.16
    // follow-up notes.
  }

  // MSVC500 keeps `for`-loop control variables in function scope; reuse
  // `node`'s declaration slot from the loop above rather than redeclaring it.
  for (node = childOrderList; node != nullptr;) {
    if (node->active_flag != 0) {
      node = node->next;
      continue;
    }

    TTaskForce* child = node->object_ptr;
    child->SetMapOrderActiveChildEntry(nullptr);

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->order_type].enabledFlagOrBucketOffset);
    short* bucketCounter =
        reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
    }
    node = DeleteMapOrderChildLinkAndReturnNext(node);
  }

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(this)) {
    g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
  }
}

// FUNCTION: IMPERIALISM 0x00553bc0
void TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink(TTaskForce* node) {
  // TODO: promote body -- searches `head` for an existing link to `node` (via
  // a sub-call at 0x40635c, not yet resolved); if none exists, allocates
  // (operator new, 0x606f73) and inserts a new TMapOrderChildLinkNode in
  // priority-sorted order (lookup table at 0x698120), bumps a bucket counter
  // at this+0x1e, sets node->owner = this, then makes a virtual dispatch
  // through this receiver's own (still-uncharted) vtable slot 0xc/4 whose
  // consequences -- including a conditional write at node+0x34, past
  // TTaskForce's own 0x34-byte size -- are not yet understood. See the
  // TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink declaration
  // comment and bd 1uj.16 follow-up notes.
  (void)node;
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::RecomputeMapOrderChildAggregateMetric() {
  activeChildEntry = nullptr;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    activeChildEntry =
        node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
}
