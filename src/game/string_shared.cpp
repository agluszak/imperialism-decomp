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
static const unsigned int kLoadResourceStringToSharedBufferAddr = 0x0060ce85;
static const unsigned int kAllocateWithFallbackHandlerAddr = 0x00606f73;
static const unsigned int kCopySharedStringBytesAddr = 0x005e9cf0;
static const unsigned int kFreeHeapBufferIfNotNullAddr = 0x00606faf;

typedef bool(__cdecl *LoadResourceStringToSharedBufferFn)(unsigned int);
typedef void *(__cdecl *AllocateWithFallbackHandlerFn)(int);
typedef void(__cdecl *CopySharedStringBytesFn)(int, LPCSTR, int);
typedef void(__cdecl *FreeHeapBufferIfNotNullFn)(int);

static SharedStringHeader *GetSharedStringHeader(int data_ptr)
{
  return reinterpret_cast<SharedStringHeader *>(data_ptr - kSharedStringHeaderSize);
}

static int PtrToInt(const void *ptr)
{
  return static_cast<int>(reinterpret_cast<unsigned long>(ptr));
}

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
  if (GetSharedStringHeader(src_data_ptr)->ref_count < 0) {
    int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
    *dst_ref_ptr = *shared_empty_ref;
    WrapperFor_CopyMemoryPossiblyOverlapping_At00605a78(dst_ref_ptr, reinterpret_cast<LPCSTR>(*src_ref_ptr));
  } else {
    *dst_ref_ptr = src_data_ptr;
    InterlockedIncrement(reinterpret_cast<LONG *>(src_data_ptr - kSharedStringHeaderSize));
  }
  return dst_ref_ptr;
}

// FUNCTION: IMPERIALISM 0x006057de
void AllocateSharedStringBufferForLength(int *ref_ptr, int text_length)
{
  if (text_length == 0) {
    int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
    *ref_ptr = *shared_empty_ref;
    return;
  }

  AllocateWithFallbackHandlerFn allocate_with_fallback_handler =
      reinterpret_cast<AllocateWithFallbackHandlerFn>(kAllocateWithFallbackHandlerAddr);
  SharedStringHeader *header = reinterpret_cast<SharedStringHeader *>(
      allocate_with_fallback_handler(text_length + kSharedStringHeaderSize + 1));
  header->ref_count = 1;
  header->text_length = text_length;
  header->capacity = text_length;
  reinterpret_cast<char *>(header)[kSharedStringHeaderSize + text_length] = '\0';
  *ref_ptr = PtrToInt(header + 1);
}

// FUNCTION: IMPERIALISM 0x0060584a
void __cdecl DecrementSharedStringRefCountAndFree(LONG *ref_count_ptr)
{
  if (ref_count_ptr != reinterpret_cast<LONG *>(kSharedEmptyHeaderAddr)) {
    LONG ref_count = InterlockedDecrement(ref_count_ptr);
    if (ref_count < 1) {
      FreeHeapBufferIfNotNullFn free_heap_buffer_if_not_null =
          reinterpret_cast<FreeHeapBufferIfNotNullFn>(kFreeHeapBufferIfNotNullAddr);
      free_heap_buffer_if_not_null(PtrToInt(ref_count_ptr));
    }
  }
}

// GHIDRA comment: small wrapper around "release + allocate" branch for shared strings.
// FUNCTION: IMPERIALISM 0x0060588b
void __fastcall EnsureUniqueSharedStringBuffer(int *ref_ptr)
{
  int old_data_ptr = *ref_ptr;
  SharedStringHeader *old_header = GetSharedStringHeader(old_data_ptr);
  if (old_header->ref_count > 1) {
    int old_text_length = old_header->text_length;
    ReleaseSharedStringRefIfNotEmpty(ref_ptr);
    AllocateSharedStringBufferForLength(ref_ptr, old_text_length);

    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(*ref_ptr, reinterpret_cast<LPCSTR>(old_data_ptr), old_text_length + 1);
  }
}

// GHIDRA [WrapperShape]: small wrapper around AllocateSharedStringBufferForLength.
// FUNCTION: IMPERIALISM 0x006058b9
void
WrapperFor_AllocateSharedStringBufferForLength_At006058b9(int *ref_ptr, int required_capacity)
{
  int data_ptr = *ref_ptr;
  SharedStringHeader *header = GetSharedStringHeader(data_ptr);
  if ((header->ref_count > 1) || (header->capacity < required_capacity)) {
    ReleaseSharedStringRefIfNotEmpty(ref_ptr);
    AllocateSharedStringBufferForLength(ref_ptr, required_capacity);
  }
}

// FUNCTION: IMPERIALISM 0x006058e2
void ReleaseSharedStringRefIfNotEmpty(int *ref_ptr)
{
  DecrementSharedStringRefCountAndFree(reinterpret_cast<LONG *>(*ref_ptr - kSharedStringHeaderSize));
}

// GHIDRA comment: Initializes from either C-string or low-word resource-id.
// FUNCTION: IMPERIALISM 0x00605950
int *ConstructSharedStringFromCStrOrResourceId(int *dst_ref_ptr, LPCSTR text_or_resource_id)
{
  int *shared_empty_ref = reinterpret_cast<int *>(GetSharedEmptyStringRef());
  *dst_ref_ptr = *shared_empty_ref;

  if ((text_or_resource_id != 0) &&
      ((static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id)) >> 16) ==
       0)) {
      LoadResourceStringToSharedBufferFn load_resource_string_to_shared_buffer =
          reinterpret_cast<LoadResourceStringToSharedBufferFn>(
              kLoadResourceStringToSharedBufferAddr);
      load_resource_string_to_shared_buffer(
          static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id)) & 0xffff);
      return dst_ref_ptr;
  }

  int text_len = 0;
  if (text_or_resource_id != 0) {
    text_len = lstrlenA(text_or_resource_id);
  }
  if (text_len != 0) {
    AllocateSharedStringBufferForLength(dst_ref_ptr, text_len);

    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(*dst_ref_ptr, text_or_resource_id, text_len);
  }
  return dst_ref_ptr;
}

// GHIDRA [WrapperShape]: small wrapper around copy + length/terminator update.
// FUNCTION: IMPERIALISM 0x006059fc
void
WrapperFor_CopyMemoryPossiblyOverlapping_At006059fc(int *ref_ptr, int new_length, LPCSTR src_text)
{
  WrapperFor_AllocateSharedStringBufferForLength_At006058b9(ref_ptr, new_length);

  CopySharedStringBytesFn copy_shared_string_bytes =
      reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
  copy_shared_string_bytes(*ref_ptr, src_text, new_length);

  SharedStringHeader *header = GetSharedStringHeader(*ref_ptr);
  header->text_length = new_length;
  reinterpret_cast<char *>(*ref_ptr)[new_length] = '\0';
}

// FUNCTION: IMPERIALISM 0x00605a29
int *StringShared::AssignFromPtr(int *dst_ref_ptr)
{
  int new_data_ptr = *dst_ref_ptr;
  if (data_ptr != new_data_ptr) {
    SharedStringHeader *old_header = GetSharedStringHeader(data_ptr);
    if (((old_header->ref_count < 0) &&
         (old_header != reinterpret_cast<SharedStringHeader *>(kSharedEmptyHeaderAddr))) ||
        (GetSharedStringHeader(new_data_ptr)->ref_count < 0)) {
      WrapperFor_CopyMemoryPossiblyOverlapping_At006059fc(
          &data_ptr, GetSharedStringHeader(new_data_ptr)->text_length, reinterpret_cast<LPCSTR>(new_data_ptr));
    } else {
      ReleaseSharedStringRefIfNotEmpty(&data_ptr);
      new_data_ptr = *dst_ref_ptr;
      data_ptr = new_data_ptr;
      InterlockedIncrement(reinterpret_cast<LONG *>(new_data_ptr - kSharedStringHeaderSize));
    }
  }
  return reinterpret_cast<int *>(this);
}

// FUNCTION: IMPERIALISM 0x00605a78
int *WrapperFor_CopyMemoryPossiblyOverlapping_At00605a78(int *ref_ptr, LPCSTR src_text)
{
  int text_len = 0;
  if (src_text != 0) {
    text_len = lstrlenA(src_text);
  }
  WrapperFor_CopyMemoryPossiblyOverlapping_At006059fc(ref_ptr, text_len, src_text);
  return ref_ptr;
}

// FUNCTION: IMPERIALISM 0x00605ae0
void ConcatenateTwoBuffersToSharedString(
    int *ref_ptr, int lhs_len, LPCSTR lhs_text, int rhs_len, LPCSTR rhs_text)
{
  if ((lhs_len + rhs_len) != 0) {
    AllocateSharedStringBufferForLength(ref_ptr, lhs_len + rhs_len);
    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(*ref_ptr, lhs_text, lhs_len);
    copy_shared_string_bytes(*ref_ptr + lhs_len, rhs_text, rhs_len);
  }
}

// FUNCTION: IMPERIALISM 0x00605c6f
void AppendBufferToSharedString(int *ref_ptr, int append_len, LPCSTR append_text)
{
  if (append_len == 0) {
    return;
  }

  int data_ptr = *ref_ptr;
  SharedStringHeader *header = GetSharedStringHeader(data_ptr);

  if ((header->ref_count < 2) && (append_len + header->text_length <= header->capacity)) {
    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(data_ptr + header->text_length, append_text, append_len);
    header = GetSharedStringHeader(*ref_ptr);
    header->text_length += append_len;
    reinterpret_cast<char *>(*ref_ptr)[header->text_length] = '\0';
    return;
  }

  ConcatenateTwoBuffersToSharedString(ref_ptr, header->text_length, reinterpret_cast<LPCSTR>(data_ptr),
      append_len, append_text);
  DecrementSharedStringRefCountAndFree(reinterpret_cast<LONG *>(data_ptr - kSharedStringHeaderSize));
}

// FUNCTION: IMPERIALISM 0x00605cce
undefined4 AssignStringSharedFromCStr(undefined4 this_ptr, LPCSTR text)
{
  int text_len = 0;
  if (text != 0) {
    text_len = lstrlenA(text);
  }
  AppendBufferToSharedString(reinterpret_cast<int *>(this_ptr), text_len, text);
  return this_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d0a
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int *src_ref_ptr)
{
  AppendBufferToSharedString(
      reinterpret_cast<int *>(this_ptr),
      GetSharedStringHeader(*src_ref_ptr)->text_length,
      reinterpret_cast<LPCSTR>(*src_ref_ptr));
  return this_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d22
int EnsureSharedStringCapacityPreserveLength(int *ref_ptr, int min_capacity)
{
  int old_data_ptr = *ref_ptr;
  SharedStringHeader *old_header = GetSharedStringHeader(old_data_ptr);

  if ((old_header->ref_count > 1) || (old_header->capacity < min_capacity)) {
    int old_length = old_header->text_length;
    if (min_capacity < old_length) {
      min_capacity = old_length;
    }
    AllocateSharedStringBufferForLength(ref_ptr, min_capacity);

    CopySharedStringBytesFn copy_shared_string_bytes =
        reinterpret_cast<CopySharedStringBytesFn>(kCopySharedStringBytesAddr);
    copy_shared_string_bytes(*ref_ptr, reinterpret_cast<LPCSTR>(old_data_ptr), old_length + 1);

    GetSharedStringHeader(*ref_ptr)->text_length = old_length;
    DecrementSharedStringRefCountAndFree(reinterpret_cast<LONG *>(old_data_ptr - kSharedStringHeaderSize));
  }
  return *ref_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d71
void SetSharedStringLengthAndTerminator(int *ref_ptr, int new_length)
{
  EnsureUniqueSharedStringBuffer(ref_ptr);
  if (new_length == -1) {
    new_length = lstrlenA(reinterpret_cast<LPCSTR>(*ref_ptr));
  }
  GetSharedStringHeader(*ref_ptr)->text_length = new_length;
  reinterpret_cast<char *>(*ref_ptr)[new_length] = '\0';
}

// GHIDRA [WrapperShape]: small wrapper around EnsureSharedStringCapacityPreserveLength.
// FUNCTION: IMPERIALISM 0x00605d99
int
WrapperFor_EnsureSharedStringCapacityPreserveLength_At00605d99(int *ref_ptr, int new_length)
{
  EnsureSharedStringCapacityPreserveLength(ref_ptr, new_length);
  GetSharedStringHeader(*ref_ptr)->text_length = new_length;
  reinterpret_cast<char *>(*ref_ptr)[new_length] = '\0';
  return *ref_ptr;
}
