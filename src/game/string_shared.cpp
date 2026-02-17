#include "game/string_shared.h"

#include <windows.h>

namespace {

struct SharedStringHeader {
  LONG ref_count;
  int text_length;
  int capacity;
};

static const int kSharedStringHeaderSize = 0x0c;
static const unsigned int kSharedEmptyStringRefAddr = 0x0069be0c;
static const unsigned int kSharedEmptyHeaderAddr = 0x0069be08;
static const unsigned int kFinalizeSharedStringRefAssignAddr = 0x00605a78;
static const unsigned int kLoadStringByIdAddr = 0x0060ce85;
static const unsigned int kReserveSharedStringBufferAddr = 0x006057de;
static const unsigned int kCopySharedStringBytesAddr = 0x005e9cf0;
static const unsigned int kAssignOwnedStringAddr = 0x006059fc;
static const unsigned int kAssignSharedByLengthAddr = 0x00605c6f;
static const unsigned int kFreeHeapBufferIfNotNullAddr = 0x00606faf;

typedef void(__cdecl *FinalizeSharedStringRefAssignFn)(int);
typedef void(__cdecl *LoadStringByIdFn)(unsigned int);
typedef void(__cdecl *ReserveSharedStringBufferFn)(int);
typedef void(__cdecl *CopySharedStringBytesFn)(int, LPCSTR, int);
typedef void(__cdecl *AssignOwnedStringFn)(int, int);
typedef void(__cdecl *AssignSharedByLengthFn)(undefined4, int, LPCSTR);
typedef void(__cdecl *FreeHeapBufferIfNotNullFn)(int);

} // namespace

// FUNCTION: IMPERIALISM 0x00605791
undefined **GetSharedEmptyStringRef(void)
{
  return reinterpret_cast<undefined **>(kSharedEmptyStringRefAddr);
}

// FUNCTION: IMPERIALISM 0x00605797
int *InitializeSharedStringRefFromEmpty(int *dst_ref_ptr)
{
  int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
  *dst_ref_ptr = *shared_empty_ref;
  return dst_ref_ptr;
}

// FUNCTION: IMPERIALISM 0x006057a7
int *StringSharedRef_AssignFromPtr(int *dst_ref_ptr, int *src_ref_ptr)
{
  int src_data_ptr = *src_ref_ptr;
  if (*reinterpret_cast<int *>(src_data_ptr - kSharedStringHeaderSize) < 0) {
    int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
    *dst_ref_ptr = *shared_empty_ref;

    FinalizeSharedStringRefAssignFn finalize_assign =
        reinterpret_cast<FinalizeSharedStringRefAssignFn>(
            kFinalizeSharedStringRefAssignAddr);
    finalize_assign(*src_ref_ptr);
  } else {
    *dst_ref_ptr = src_data_ptr;
    InterlockedIncrement(reinterpret_cast<LONG *>(src_data_ptr - kSharedStringHeaderSize));
  }
  return dst_ref_ptr;
}

// FUNCTION: IMPERIALISM 0x006058e2
void ReleaseSharedStringRefIfNotEmpty(int *ref_ptr)
{
  LONG *ref_count_ptr = reinterpret_cast<LONG *>(*ref_ptr - kSharedStringHeaderSize);
  if (ref_count_ptr != reinterpret_cast<LONG *>(kSharedEmptyHeaderAddr)) {
    LONG ref_count = InterlockedDecrement(ref_count_ptr);
    if (ref_count < 1) {
      FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
          reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
      free_heap_buffer_if_not_null(*ref_ptr - kSharedStringHeaderSize);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00605950
int *ConstructSharedStringFromCStrOrResourceId(int *dst_ref_ptr, LPCSTR text_or_resource_id)
{
  int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
  *dst_ref_ptr = *shared_empty_ref;

  if (text_or_resource_id != 0) {
    if ((static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id)) >> 16) ==
        0) {
      LoadStringByIdFn load_string_by_id = reinterpret_cast<LoadStringByIdFn>(kLoadStringByIdAddr);
      load_string_by_id(
          static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id)) & 0xffff);
      return dst_ref_ptr;
    }
  }

  int text_len = 0;
  if (text_or_resource_id != 0) {
    text_len = lstrlenA(text_or_resource_id);
  }
  if (text_len != 0) {
    ReserveSharedStringBufferFn reserve_shared_string_buffer =
        reinterpret_cast<ReserveSharedStringBufferFn>(kReserveSharedStringBufferAddr);
    reserve_shared_string_buffer(text_len);

    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(*dst_ref_ptr, text_or_resource_id, text_len);
  }
  return dst_ref_ptr;
}

// FUNCTION: IMPERIALISM 0x00605a29
int *StringShared::AssignFromPtr(int *dst_ref_ptr)
{
  int new_data_ptr = *dst_ref_ptr;
  if (data_ptr != new_data_ptr) {
    SharedStringHeader *old_header =
        reinterpret_cast<SharedStringHeader *>(data_ptr - kSharedStringHeaderSize);
    if (((old_header->ref_count < 0) &&
         (old_header != reinterpret_cast<SharedStringHeader *>(kSharedEmptyHeaderAddr))) ||
        (*reinterpret_cast<LONG *>(new_data_ptr - kSharedStringHeaderSize) < 0)) {
      AssignOwnedStringFn assign_owned_string =
          reinterpret_cast<AssignOwnedStringFn>(kAssignOwnedStringAddr);
      assign_owned_string(*reinterpret_cast<int *>(new_data_ptr - 8), new_data_ptr);
    } else {
      LONG *ref_count_ptr = reinterpret_cast<LONG *>(data_ptr - kSharedStringHeaderSize);
      if (ref_count_ptr != reinterpret_cast<LONG *>(kSharedEmptyHeaderAddr)) {
        LONG ref_count = InterlockedDecrement(ref_count_ptr);
        if (ref_count < 1) {
          FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
              reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
          free_heap_buffer_if_not_null(data_ptr - kSharedStringHeaderSize);
        }
      }
      new_data_ptr = *dst_ref_ptr;
      data_ptr = new_data_ptr;
      InterlockedIncrement(reinterpret_cast<LONG *>(new_data_ptr - kSharedStringHeaderSize));
    }
  }
  return reinterpret_cast<int *>(this);
}

// FUNCTION: IMPERIALISM 0x00605cce
undefined4 AssignStringSharedFromCStr(undefined4 this_ptr, LPCSTR text)
{
  int text_len = 0;
  if (text != 0) {
    text_len = lstrlenA(text);
  }

  AssignSharedByLengthFn assign_shared_by_length =
      reinterpret_cast<AssignSharedByLengthFn>(kAssignSharedByLengthAddr);
  assign_shared_by_length(this_ptr, text_len, text);
  return this_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d0a
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int *src_ref_ptr)
{
  AssignSharedByLengthFn assign_shared_by_length =
      reinterpret_cast<AssignSharedByLengthFn>(kAssignSharedByLengthAddr);
  assign_shared_by_length(
      this_ptr,
      *reinterpret_cast<int *>(*src_ref_ptr - 8),
      reinterpret_cast<LPCSTR>(*src_ref_ptr));
  return this_ptr;
}
