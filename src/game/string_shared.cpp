#include "game/string_shared.h"

#include <windows.h>

// Most CString shared-buffer routines match best favor-size + FPO ("ys"); a
// few (the concat-assign wrappers and the ref-assign path) regress badly under
// it and are bracketed back to the build default below.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 CopyMemoryPossiblyOverlapping(void);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

static const int kSharedStringHeaderSize = 0x0c;
static const unsigned int kSharedEmptyStringRefAddr = 0x0069be0c;
static const unsigned int kSharedEmptyHeaderAddr = 0x0069be08;

static SharedStringHeader* GetSharedStringHeader(int data_ptr) {
  return reinterpret_cast<SharedStringHeader*>(data_ptr - kSharedStringHeaderSize);
}

static __inline int PtrToInt(const void* ptr) {
  return static_cast<int>(reinterpret_cast<unsigned long>(ptr));
}

} // namespace

SharedStringHeader* StringShared::Header() {
  return GetSharedStringHeader(data_ptr);
}

const SharedStringHeader* StringShared::Header() const {
  return GetSharedStringHeader(data_ptr);
}

const char* StringShared::Text() const {
  return reinterpret_cast<const char*>(data_ptr);
}

int StringShared::Length() const {
  return Header()->text_length;
}

int StringShared::Capacity() const {
  return Header()->capacity;
}

// FUNCTION: IMPERIALISM 0x006057de
void StringShared::AllocateBufferForLength(int text_length) {
  if (text_length == 0) {
    InitFromEmpty();
    return;
  }

  SharedStringHeader* header = reinterpret_cast<SharedStringHeader*>(
      AllocateWithFallbackHandler(text_length + kSharedStringHeaderSize + 1));
  header->ref_count = 1;
  header->text_length = text_length;
  header->capacity = text_length;
  reinterpret_cast<char*>(header)[kSharedStringHeaderSize + text_length] = '\0';
  data_ptr = PtrToInt(header + 1);
}

// FUNCTION: IMPERIALISM 0x00605791
undefined** GetSharedEmptyStringRef(void) {
  return reinterpret_cast<undefined**>(kSharedEmptyStringRefAddr);
}

// FUNCTION: IMPERIALISM 0x00605797
StringShared* StringShared::InitFromEmpty() {
  int* shared_empty_ref = reinterpret_cast<int*>(GetSharedEmptyStringRef());
  data_ptr = *shared_empty_ref;
  return this;
}

// FUNCTION: IMPERIALISM 0x006057a7
StringShared* StringShared::StringSharedRef_AssignFromPtr(const StringShared& src_ref) {
  int src_data_ptr = src_ref.data_ptr;
  if (GetSharedStringHeader(src_data_ptr)->ref_count < 0) {
    int* shared_empty_ref = reinterpret_cast<int*>(GetSharedEmptyStringRef());
    data_ptr = *shared_empty_ref;
    CopyFromCStr(reinterpret_cast<const char*>(src_data_ptr));
  } else {
    data_ptr = src_data_ptr;
    InterlockedIncrement(reinterpret_cast<LONG*>(src_data_ptr - kSharedStringHeaderSize));
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x0060584a
void __cdecl DecrementSharedStringRefCountAndFree(LONG* ref_count_ptr) {
  if (ref_count_ptr != reinterpret_cast<LONG*>(kSharedEmptyHeaderAddr)) {
    LONG ref_count = InterlockedDecrement(ref_count_ptr);
    if (ref_count < 1) {
      FreeHeapBufferIfNotNull(PtrToInt(ref_count_ptr));
    }
  }
}

// GHIDRA comment: small wrapper around "release + allocate" branch for shared strings.

// FUNCTION: IMPERIALISM 0x0060588b
void StringShared::EnsureUniqueSharedStringBuffer() {
  int old_data_ptr = data_ptr;
  SharedStringHeader* old_header = Header();
  if (old_header->ref_count > 1) {
    int old_text_length = old_header->text_length;
    this->~StringShared();
    AllocateBufferForLength(old_text_length);

    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, reinterpret_cast<const char*>(old_data_ptr), old_text_length + 1);
  }
}

// FUNCTION: IMPERIALISM 0x006058b9
void StringShared::EnsureCapacityOrAllocate(int required_capacity) {
  SharedStringHeader* header = Header();
  if ((header->ref_count > 1) || (header->capacity < required_capacity)) {
    this->~StringShared();
    AllocateBufferForLength(required_capacity);
  }
}

// FUNCTION: IMPERIALISM 0x006058e2
StringShared::~StringShared() {
  LONG* ref_count_ptr = reinterpret_cast<LONG*>(data_ptr - kSharedStringHeaderSize);
  if (ref_count_ptr != reinterpret_cast<LONG*>(kSharedEmptyHeaderAddr)) {
    LONG ref_count = InterlockedDecrement(ref_count_ptr);
    if (ref_count < 1) {
      FreeHeapBufferIfNotNull(PtrToInt(ref_count_ptr));
    }
  }
}

// GHIDRA comment: Initializes from either C-string or low-word resource-id.
// FUNCTION: IMPERIALISM 0x00605950
StringShared* StringShared::ConstructFromCStrOrResourceId(const char* text_or_resource_id) {
  int* shared_empty_ref = reinterpret_cast<int*>(GetSharedEmptyStringRef());
  data_ptr = *shared_empty_ref;

  unsigned int text_ptr =
      static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id));
  if ((text_ptr != 0) && ((text_ptr >> 16) == 0)) {
    LoadResourceStringToSharedBuffer(text_ptr & 0xffff);
    return this;
  }

  int text_len = 0;
  if (text_or_resource_id != 0) {
    text_len = lstrlenA(text_or_resource_id);
  }
  if (text_len != 0) {
    AllocateBufferForLength(text_len);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, text_or_resource_id, text_len);
  }
  return this;
}

// GHIDRA [WrapperShape]: small wrapper around copy + length/terminator update.

// FUNCTION: IMPERIALISM 0x006059fc
void StringShared::CopyBufferAndSetLength(int new_length, const char* src_text) {
  EnsureCapacityOrAllocate(new_length);
  reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
      data_ptr, src_text, new_length);

  SharedStringHeader* header = Header();
  header->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
}

// FUNCTION: IMPERIALISM 0x00605a29
StringShared* StringShared::AssignFromPtr(const StringShared& src_ref) {
  int new_data_ptr = src_ref.data_ptr;
  if (data_ptr != new_data_ptr) {
    SharedStringHeader* old_header = GetSharedStringHeader(data_ptr);
    if (((old_header->ref_count < 0) &&
         (old_header != reinterpret_cast<SharedStringHeader*>(kSharedEmptyHeaderAddr))) ||
        (GetSharedStringHeader(new_data_ptr)->ref_count < 0)) {
      CopyBufferAndSetLength(GetSharedStringHeader(new_data_ptr)->text_length,
                             reinterpret_cast<const char*>(new_data_ptr));
    } else {
      this->~StringShared();
      new_data_ptr = src_ref.data_ptr;
      data_ptr = new_data_ptr;
      InterlockedIncrement(reinterpret_cast<LONG*>(new_data_ptr - kSharedStringHeaderSize));
    }
  }
  return this;
}

StringShared* StringShared::AssignFromRef(const StringShared& src_ref) {
  return AssignFromPtr(src_ref);
}

// FUNCTION: IMPERIALISM 0x00605a78
StringShared* StringShared::CopyFromCStr(const char* src_text) {
  int text_len = 0;
  if (src_text != 0) {
    text_len = lstrlenA(src_text);
  }
  CopyBufferAndSetLength(text_len, src_text);
  return this;
}

// FUNCTION: IMPERIALISM 0x00605ae0
void StringShared::ConcatenateBuffers(int lhs_len, const char* lhs_text, int rhs_len,
                                      const char* rhs_text) {
  if ((lhs_len + rhs_len) != 0) {
    AllocateBufferForLength(lhs_len + rhs_len);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, lhs_text, lhs_len);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr + lhs_len, rhs_text, rhs_len);
  }
}

void StringShared::AssignConcatRefAndRef(const StringShared& lhs_ref, const StringShared& rhs_ref) {
  StringShared concat_ref;
  concat_ref.InitFromEmpty();

  concat_ref.ConcatenateBuffers(lhs_ref.Length(), lhs_ref.Text(), rhs_ref.Length(), rhs_ref.Text());
  AssignFromRef(concat_ref);
}

void StringShared::AssignConcatRefAndCStr(const StringShared& lhs_ref, const char* rhs_text) {
  StringShared concat_ref;
  concat_ref.InitFromEmpty();

  int rhs_length = 0;
  if (rhs_text != 0) {
    rhs_length = lstrlenA(rhs_text);
  }

  concat_ref.ConcatenateBuffers(lhs_ref.Length(), lhs_ref.Text(), rhs_length, rhs_text);
  AssignFromRef(concat_ref);
}

void StringShared::AssignConcatCStrAndRef(const char* lhs_text, const StringShared& rhs_ref) {
  StringShared concat_ref;
  concat_ref.InitFromEmpty();

  int lhs_length = 0;
  if (lhs_text != 0) {
    lhs_length = lstrlenA(lhs_text);
  }

  concat_ref.ConcatenateBuffers(lhs_length, lhs_text, rhs_ref.Length(), rhs_ref.Text());
  AssignFromRef(concat_ref);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x00605b21
void AssignSharedStringConcatRefAndRef(int* dst_ref_ptr, int* lhs_ref_ptr, int* rhs_ref_ptr) {
  StringShared* dst_ref = reinterpret_cast<StringShared*>(dst_ref_ptr);
  StringShared* lhs_ref = reinterpret_cast<StringShared*>(lhs_ref_ptr);
  StringShared* rhs_ref = reinterpret_cast<StringShared*>(rhs_ref_ptr);
  dst_ref->AssignConcatRefAndRef(*lhs_ref, *rhs_ref);
}

// FUNCTION: IMPERIALISM 0x00605b87
void __stdcall AssignSharedStringConcatRefAndCStr(int* dst_ref_ptr, int* lhs_ref_ptr,
                                                  const char* rhs_text) {
  StringShared* dst_ref = reinterpret_cast<StringShared*>(dst_ref_ptr);
  StringShared* lhs_ref = reinterpret_cast<StringShared*>(lhs_ref_ptr);
  dst_ref->AssignConcatRefAndCStr(*lhs_ref, rhs_text);
}

// FUNCTION: IMPERIALISM 0x00605bfb
void AssignSharedStringConcatCStrAndRef(int* dst_ref_ptr, const char* lhs_text, int* rhs_ref_ptr) {
  StringShared* dst_ref = reinterpret_cast<StringShared*>(dst_ref_ptr);
  StringShared* rhs_ref = reinterpret_cast<StringShared*>(rhs_ref_ptr);
  dst_ref->AssignConcatCStrAndRef(lhs_text, *rhs_ref);
}

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// FUNCTION: IMPERIALISM 0x00605c6f
void StringShared::AppendBuffer(int append_len, const char* append_text) {
  if (append_len == 0) {
    return;
  }

  int old_data_ptr = data_ptr;
  SharedStringHeader* header = Header();

  if ((header->ref_count < 2) && (append_len + header->text_length <= header->capacity)) {
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr + header->text_length, append_text, append_len);
    header = Header();
    header->text_length += append_len;
    reinterpret_cast<char*>(data_ptr)[header->text_length] = '\0';
    return;
  }

  ConcatenateBuffers(header->text_length, reinterpret_cast<const char*>(old_data_ptr), append_len,
                     append_text);
  DecrementSharedStringRefCountAndFree(
      reinterpret_cast<LONG*>(old_data_ptr - kSharedStringHeaderSize));
}

// FUNCTION: IMPERIALISM 0x00605cce
undefined4 StringShared::AssignFromCStr(const char* text) {
  int text_len = 0;
  if (text != 0) {
    text_len = lstrlenA(text);
  }
  AppendBuffer(text_len, text);
  return reinterpret_cast<undefined4>(this);
}

// FUNCTION: IMPERIALISM 0x00605cf5
int __fastcall AppendSingleByteToSharedStringFromArg(int* ref_ptr, int, int append_byte) {
  char append_text[2];
  append_text[0] = static_cast<char>(append_byte);
  append_text[1] = '\0';
  reinterpret_cast<StringShared*>(ref_ptr)->AppendBuffer(1, append_text);
  return PtrToInt(ref_ptr);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x00605d0a
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr) {
  return reinterpret_cast<StringShared*>(this_ptr)->AssignFromSharedRef(
      *reinterpret_cast<const StringShared*>(src_ref_ptr));
}

undefined4 StringShared::AssignFromSharedRef(const StringShared& src_ref) {
  AppendBuffer(src_ref.Length(), src_ref.Text());
  return reinterpret_cast<undefined4>(this);
}

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// FUNCTION: IMPERIALISM 0x00605d22
int StringShared::EnsureCapacityPreserveLength(int min_capacity) {
  int old_data_ptr = data_ptr;
  SharedStringHeader* old_header = Header();

  if ((old_header->ref_count > 1) || (old_header->capacity < min_capacity)) {
    int old_length = old_header->text_length;
    if (min_capacity < old_length) {
      min_capacity = old_length;
    }
    AllocateBufferForLength(min_capacity);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, reinterpret_cast<const char*>(old_data_ptr), old_length + 1);
    Header()->text_length = old_length;
    DecrementSharedStringRefCountAndFree(
        reinterpret_cast<LONG*>(old_data_ptr - kSharedStringHeaderSize));
  }
  return data_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d99
int StringShared::EnsureCapacityAndSetLength(int new_length) {
  EnsureCapacityPreserveLength(new_length);
  Header()->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
  return data_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d71
void StringShared::SetLengthAndTerminator(int new_length) {
  EnsureUniqueSharedStringBuffer();
  if (new_length == -1) {
    new_length = lstrlenA(Text());
  }
  Header()->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
}

