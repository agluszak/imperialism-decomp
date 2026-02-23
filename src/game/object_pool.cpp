#include "game/object_pool.h"

namespace {

static const unsigned int kRebuildActiveNodeAddr = 0x00550670;
static const unsigned int kDestroyNodeAddr = 0x00553bc0;
static const unsigned int kAllocateWithFallbackHandlerAddr = 0x00606f73;
static const unsigned int kFreeHeapBufferIfNotNullAddr = 0x00606faf;
static const unsigned int kOrderTypeToBucketOffsetTableAddr = 0x00698120;
static const int kOwnerBucketCountsBaseOffset = 0x18;

typedef int(__cdecl *RebuildActiveNodeFn)(int, int);
typedef void(__cdecl *DestroyNodeFn)(void *);
typedef void(__cdecl *FreeHeapBufferIfNotNullFn)(void *);
typedef int(__cdecl *AllocateWithFallbackHandlerFn)(undefined4);

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
};

} // namespace

// GHIDRA comment: Setting prototype: void* FindMapOrderChildNodeById(int nChildNodeId).
// FUNCTION: IMPERIALISM 0x00552510
ObjectPoolListNode *FindMissionOrderNodeById(ObjectPoolListNode *node, int child_node_id)
{
  while (node != 0) {
    if (node->object_ptr == child_node_id) {
      return node;
    }
    node = node->next;
  }
  return 0;
}

// GHIDRA comment: Setting prototype: int *DeleteMapOrderChildLinkAndReturnNext(int *pChildLinkNode).
// FUNCTION: IMPERIALISM 0x00552590
ObjectPoolListNode * __fastcall DeleteMapOrderChildLinkAndReturnNext(
    ObjectPoolListNode *child_link_node)
{
  ObjectPoolListNode *next_node = child_link_node->next;
  if (next_node != 0) {
    next_node->prev_node_ptr = child_link_node->prev_node_ptr;
  }
  if (child_link_node->prev_node_ptr != 0) {
    *reinterpret_cast<int *>(child_link_node->prev_node_ptr + 4) =
        reinterpret_cast<int>(child_link_node->next);
  }

  FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
      reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
  free_heap_buffer_if_not_null(child_link_node);
  return next_node;
}

// GHIDRA comment: recursively removes linked-list node by value.
// FUNCTION: IMPERIALISM 0x005525d0
void __cdecl RemoveLinkedOrderNodeByValueRecursive(
    ObjectPoolListNode *node, int child_node_id)
{
  if (node == 0) {
    return;
  }

  if (node->object_ptr == child_node_id) {
    if (node->next != 0) {
      node->next->prev_node_ptr = node->prev_node_ptr;
    }
    if (node->prev_node_ptr != 0) {
      *reinterpret_cast<int *>(node->prev_node_ptr + 4) = reinterpret_cast<int>(node->next);
    }
    FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
        reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
    free_heap_buffer_if_not_null(node);
    return;
  }

  RemoveLinkedOrderNodeByValueRecursive(node->next, child_node_id);
}

// FUNCTION: IMPERIALISM 0x00552650
ObjectPoolListNode *CreateLinkedOrderNode(
    ObjectPoolListNode *next_node, int child_node_id)
{
  AllocateWithFallbackHandlerFn allocate_with_fallback_handler =
      reinterpret_cast<AllocateWithFallbackHandlerFn>(kAllocateWithFallbackHandlerAddr);
  ObjectPoolListNode *new_node =
      reinterpret_cast<ObjectPoolListNode *>(allocate_with_fallback_handler(0x10));
  if (new_node == 0) {
    return 0;
  }

  new_node->object_ptr = child_node_id;
  new_node->next = next_node;
  new_node->prev_node_ptr = 0;
  new_node->active_flag = 1;
  new_node->pad_0d = 0;
  new_node->pad_0e = 0;
  new_node->pad_0f = 0;

  if (next_node != 0) {
    next_node->prev_node_ptr = reinterpret_cast<int>(new_node);
  }
  if (new_node->prev_node_ptr != 0) {
    *reinterpret_cast<ObjectPoolListNode **>(new_node->prev_node_ptr + 4) = new_node;
  }
  return new_node;
}

// GHIDRA comment: Setting prototype:
// int *PruneDefeatedMapOrderChildrenAndReturnHead(int *pChildLinkHead).
// FUNCTION: IMPERIALISM 0x005526e0
ObjectPoolListNode * __fastcall PruneDefeatedMapOrderChildrenAndReturnHead(
    ObjectPoolListNode *child_link_head)
{
  while (true) {
    if (child_link_head == 0) {
      return 0;
    }

    int child_node = child_link_head->object_ptr;
    if (0 < *reinterpret_cast<short *>(child_node + 0x1c)) {
      break;
    }

    *reinterpret_cast<int *>(child_node + 0xc) = 0;
    reinterpret_cast<TaskForceOrderVirtual *>(child_node)->Slot1C();
    child_link_head = DeleteMapOrderChildLinkAndReturnNext(child_link_head);
  }

  PruneDefeatedMapOrderChildrenAndReturnHead(child_link_head->next);
  return child_link_head;
}

// FUNCTION: IMPERIALISM 0x005528c0
void __cdecl NoOpTaskForceVtableSlot(void)
{
  return;
}

// GHIDRA comment: Setting prototype:
// void RelinkMapOrderQueueNodeBetween(int pPrevNode, int pNextNode).
// FUNCTION: IMPERIALISM 0x005528e0
void RelinkMapOrderQueueNodeBetween(void *node_this, int prev_node, int next_node)
{
  char *node_bytes = reinterpret_cast<char *>(node_this);
  int old_prev_node = *reinterpret_cast<int *>(node_bytes + 0x28);
  int old_next_node = *reinterpret_cast<int *>(node_bytes + 0x2c);

  if (old_prev_node != 0) {
    *reinterpret_cast<int *>(old_prev_node + 0x2c) = old_next_node;
  }
  if (old_next_node != 0) {
    *reinterpret_cast<int *>(old_next_node + 0x28) = old_prev_node;
  }

  *reinterpret_cast<int *>(node_bytes + 0x28) = prev_node;
  *reinterpret_cast<int *>(node_bytes + 0x2c) = next_node;

  if (prev_node != 0) {
    *reinterpret_cast<void **>(prev_node + 0x2c) = node_this;
  }
  if (*reinterpret_cast<int *>(node_bytes + 0x2c) != 0) {
    *reinterpret_cast<void **>(*reinterpret_cast<int *>(node_bytes + 0x2c) + 0x28) = node_this;
  }
}

// FUNCTION: IMPERIALISM 0x00550f80
void __fastcall DecrementOrderNodeRequiredCount(void *order_node, short decrement)
{
  short *required_count = reinterpret_cast<short *>(reinterpret_cast<char *>(order_node) + 0x1c);
  *required_count = static_cast<short>(*required_count - decrement);
}

// FUNCTION: IMPERIALISM 0x00550ff0
void ObjectPool::RemoveNode(int self)
{
  ObjectPoolOwner *owner_ctx = owner;
  if (owner_ctx != 0) {
    ObjectPoolListNode *list_head = owner_ctx->head;

    if ((list_head != 0) && (this != reinterpret_cast<void *>(list_head->object_ptr))) {
      list_head = FindMissionOrderNodeById(list_head->next, reinterpret_cast<int>(this));
    }

    if (list_head != 0) {
      list_head = owner_ctx->head;
      if (list_head != 0) {
        if (this == reinterpret_cast<void *>(list_head->object_ptr)) {
          list_head = DeleteMapOrderChildLinkAndReturnNext(list_head);
        } else {
          RemoveLinkedOrderNodeByValueRecursive(list_head->next, reinterpret_cast<int>(this));
        }
      }

      owner_ctx->head = list_head;

      const short *order_type_to_bucket_offset =
          reinterpret_cast<const short *>(kOrderTypeToBucketOffsetTableAddr + order_type * 0x24);
      short bucket_offset = *order_type_to_bucket_offset;
      short *bucket_counter = reinterpret_cast<short *>(
          reinterpret_cast<char *>(owner_ctx) + kOwnerBucketCountsBaseOffset + bucket_offset * 2);
      *bucket_counter = *bucket_counter - 1;
    }

    if (this == reinterpret_cast<void *>(owner_ctx->active_node)) {
      list_head = owner_ctx->head;
      owner_ctx->active_node = 0;
      for (; list_head != 0; list_head = list_head->next) {
        RebuildActiveNodeFn rebuild_active_node =
            reinterpret_cast<RebuildActiveNodeFn>(kRebuildActiveNodeAddr);
        int new_head = rebuild_active_node(owner_ctx->active_node, 0);
        owner_ctx->active_node = new_head;
      }
    }

    owner = 0;
  }

  if (self != 0) {
    DestroyNodeFn destroy_node = reinterpret_cast<DestroyNodeFn>(kDestroyNodeAddr);
    destroy_node(this);
  }
}
