#include "game/object_pool.h"

namespace {

static const unsigned int kFindMissionOrderNodeByIdAddr = 0x00552510;
static const unsigned int kRemoveNodeFromChainAddr = 0x005525d0;
static const unsigned int kRebuildActiveNodeAddr = 0x00550670;
static const unsigned int kDestroyNodeAddr = 0x00553bc0;
static const unsigned int kFreeHeapBufferIfNotNullAddr = 0x00606faf;
static const unsigned int kOrderTypeToBucketOffsetTableAddr = 0x00698120;
static const int kOwnerBucketCountsBaseOffset = 0x18;

typedef ObjectPoolListNode *(__cdecl *FindMissionOrderNodeByIdFn)(void *, int);
typedef void(__cdecl *RemoveNodeFromChainFn)(void *);
typedef int(__cdecl *RebuildActiveNodeFn)(int, int);
typedef void(__cdecl *DestroyNodeFn)(void *);
typedef void(__cdecl *FreeHeapBufferIfNotNullFn)(void *);

} // namespace

// FUNCTION: IMPERIALISM 0x00550ff0
void ObjectPool::RemoveNode(int self)
{
  ObjectPoolOwner *owner_ctx = owner;
  if (owner_ctx != 0) {
    ObjectPoolListNode *list_head = owner_ctx->head;

    if ((list_head != 0) && (this != reinterpret_cast<void *>(list_head->object_ptr))) {
      FindMissionOrderNodeByIdFn find_mission_order_node_by_id =
          reinterpret_cast<FindMissionOrderNodeByIdFn>(kFindMissionOrderNodeByIdAddr);
      list_head = find_mission_order_node_by_id(
          reinterpret_cast<void *>(list_head->next), reinterpret_cast<int>(this));
    }

    if (list_head != 0) {
      list_head = owner_ctx->head;
      if (list_head != 0) {
        if (this == reinterpret_cast<void *>(list_head->object_ptr)) {
          ObjectPoolListNode *next_node = list_head->next;
          if (next_node != 0) {
            next_node->prev_node_ptr = list_head->prev_node_ptr;
          }
          if (list_head->prev_node_ptr != 0) {
            *reinterpret_cast<int *>(list_head->prev_node_ptr + 4) =
                reinterpret_cast<int>(list_head->next);
          }
          FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
              reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
          free_heap_buffer_if_not_null(list_head);
          list_head = next_node;
        } else {
          RemoveNodeFromChainFn remove_node_from_chain =
              reinterpret_cast<RemoveNodeFromChainFn>(kRemoveNodeFromChainAddr);
          remove_node_from_chain(this);
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
