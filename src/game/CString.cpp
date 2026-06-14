#include "game/CString.h"

#include <new>
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

SharedStringHeader* CString::Header() {
  return GetSharedStringHeader(data_ptr);
}

const SharedStringHeader* CString::Header() const {
  return GetSharedStringHeader(data_ptr);
}

const char* CString::Text() const {
  return reinterpret_cast<const char*>(data_ptr);
}

int CString::Length() const {
  return Header()->text_length;
}

int CString::Capacity() const {
  return Header()->capacity;
}

// FUNCTION: IMPERIALISM 0x006057de
void CString::AllocateBufferForLength(int text_length) {
  if (text_length == 0) {
    new (this) CString(); // re-init this (already released by caller) -> 0x00605797
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
CString::CString() {
  int* shared_empty_ref = reinterpret_cast<int*>(GetSharedEmptyStringRef());
  data_ptr = *shared_empty_ref;
}

// FUNCTION: IMPERIALISM 0x006057a7
CString* CString::StringSharedRef_AssignFromPtr(const CString& src_ref) {
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
void CString::EnsureUniqueSharedStringBuffer() {
  int old_data_ptr = data_ptr;
  SharedStringHeader* old_header = Header;
  if (old_header->ref_count > 1) {
    int old_text_length = old_header->text_length;
    this->~CString();
    AllocateBufferForLength(old_text_length);

    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, reinterpret_cast<const char*>(old_data_ptr), old_text_length + 1);
  }
}

// FUNCTION: IMPERIALISM 0x006058b9
void CString::EnsureCapacityOrAllocate(int required_capacity) {
  SharedStringHeader* header = Header;
  if ((header->ref_count > 1) || (header->capacity < required_capacity)) {
    this->~CString();
    AllocateBufferForLength(required_capacity);
  }
}

// FUNCTION: IMPERIALISM 0x006058e2
CString::~CString() {
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
CString::CString(const char* text_or_resource_id) {
  int* shared_empty_ref = reinterpret_cast<int*>(GetSharedEmptyStringRef());
  data_ptr = *shared_empty_ref;

  unsigned int text_ptr =
      static_cast<unsigned int>(reinterpret_cast<unsigned long>(text_or_resource_id));
  if ((text_ptr != 0) && ((text_ptr >> 16) == 0)) {
    LoadResourceStringToSharedBuffer(text_ptr & 0xffff);
    return;
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
}

// GHIDRA [WrapperShape]: small wrapper around copy + length/terminator update.

// FUNCTION: IMPERIALISM 0x006059fc
void CString::CopyBufferAndSetLength(int new_length, const char* src_text) {
  EnsureCapacityOrAllocate(new_length);
  reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
      data_ptr, src_text, new_length);

  SharedStringHeader* header = Header;
  header->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
}

// FUNCTION: IMPERIALISM 0x00605a29
CString* CString::AssignFromPtr(const CString& src_ref) {
  int new_data_ptr = src_ref.data_ptr;
  if (data_ptr != new_data_ptr) {
    SharedStringHeader* old_header = GetSharedStringHeader(data_ptr);
    if (((old_header->ref_count < 0) &&
         (old_header != reinterpret_cast<SharedStringHeader*>(kSharedEmptyHeaderAddr))) ||
        (GetSharedStringHeader(new_data_ptr)->ref_count < 0)) {
      CopyBufferAndSetLength(GetSharedStringHeader(new_data_ptr)->text_length,
                             reinterpret_cast<const char*>(new_data_ptr));
    } else {
      this->~CString();
      new_data_ptr = src_ref.data_ptr;
      data_ptr = new_data_ptr;
      InterlockedIncrement(reinterpret_cast<LONG*>(new_data_ptr - kSharedStringHeaderSize));
    }
  }
  return this;
}

CString* CString::AssignFromRef(const CString& src_ref) {
  return AssignFromPtr(src_ref);
}

// FUNCTION: IMPERIALISM 0x00605a78
CString* CString::CopyFromCStr(const char* src_text) {
  int text_len = 0;
  if (src_text != 0) {
    text_len = lstrlenA(src_text);
  }
  CopyBufferAndSetLength(text_len, src_text);
  return this;
}

// FUNCTION: IMPERIALISM 0x00605ae0
void CString::ConcatenateBuffers(int lhs_len, const char* lhs_text, int rhs_len,
                                 const char* rhs_text) {
  if ((lhs_len + rhs_len) != 0) {
    AllocateBufferForLength(lhs_len + rhs_len);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr, lhs_text, lhs_len);
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr + lhs_len, rhs_text, rhs_len);
  }
}

void CString::AssignConcatRefAndRef(const CString& lhs_ref, const CString& rhs_ref) {
  CString concat_ref;

  concat_ref.ConcatenateBuffers(lhs_ref.Length(), lhs_ref.Text(), rhs_ref.Length(), rhs_ref.Text());
  AssignFromRef(concat_ref);
}

void CString::AssignConcatRefAndCStr(const CString& lhs_ref, const char* rhs_text) {
  CString concat_ref;

  int rhs_length = 0;
  if (rhs_text != 0) {
    rhs_length = lstrlenA(rhs_text);
  }

  concat_ref.ConcatenateBuffers(lhs_ref.Length(), lhs_ref.Text(), rhs_length, rhs_text);
  AssignFromRef(concat_ref);
}

void CString::AssignConcatCStrAndRef(const char* lhs_text, const CString& rhs_ref) {
  CString concat_ref;

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
  CString* dst_ref = reinterpret_cast<CString*>(dst_ref_ptr);
  CString* lhs_ref = reinterpret_cast<CString*>(lhs_ref_ptr);
  CString* rhs_ref = reinterpret_cast<CString*>(rhs_ref_ptr);
  dst_ref->AssignConcatRefAndRef(*lhs_ref, *rhs_ref);
}

// FUNCTION: IMPERIALISM 0x00605b87
void __stdcall AssignSharedStringConcatRefAndCStr(int* dst_ref_ptr, int* lhs_ref_ptr,
                                                  const char* rhs_text) {
  CString* dst_ref = reinterpret_cast<CString*>(dst_ref_ptr);
  CString* lhs_ref = reinterpret_cast<CString*>(lhs_ref_ptr);
  dst_ref->AssignConcatRefAndCStr(*lhs_ref, rhs_text);
}

// FUNCTION: IMPERIALISM 0x00605bfb
void AssignSharedStringConcatCStrAndRef(int* dst_ref_ptr, const char* lhs_text, int* rhs_ref_ptr) {
  CString* dst_ref = reinterpret_cast<CString*>(dst_ref_ptr);
  CString* rhs_ref = reinterpret_cast<CString*>(rhs_ref_ptr);
  dst_ref->AssignConcatCStrAndRef(lhs_text, *rhs_ref);
}

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// FUNCTION: IMPERIALISM 0x00605c6f
void CString::AppendBuffer(int append_len, const char* append_text) {
  if (append_len == 0) {
    return;
  }

  int old_data_ptr = data_ptr;
  SharedStringHeader* header = Header;

  if ((header->ref_count < 2) && (append_len + header->text_length <= header->capacity)) {
    reinterpret_cast<void(__cdecl*)(int, const char*, int)>(CopyMemoryPossiblyOverlapping)(
        data_ptr + header->text_length, append_text, append_len);
    header = Header;
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
undefined4 CString::AssignFromCStr(const char* text) {
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
  reinterpret_cast<CString*>(ref_ptr)->AppendBuffer(1, append_text);
  return PtrToInt(ref_ptr);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x00605d0a
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr) {
  return reinterpret_cast<CString*>(this_ptr)->AssignFromSharedRef(
      *reinterpret_cast<const CString*>(src_ref_ptr));
}

undefined4 CString::AssignFromSharedRef(const CString& src_ref) {
  AppendBuffer(src_ref.Length(), src_ref.Text());
  return reinterpret_cast<undefined4>(this);
}

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// FUNCTION: IMPERIALISM 0x00605d22
int CString::EnsureCapacityPreserveLength(int min_capacity) {
  int old_data_ptr = data_ptr;
  SharedStringHeader* old_header = Header;

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
int CString::EnsureCapacityAndSetLength(int new_length) {
  EnsureCapacityPreserveLength(new_length);
  Header()->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
  return data_ptr;
}

// FUNCTION: IMPERIALISM 0x00605d71
void CString::SetLengthAndTerminator(int new_length) {
  EnsureUniqueSharedStringBuffer();
  if (new_length == -1) {
    new_length = lstrlenA(Text());
  }
  Header()->text_length = new_length;
  reinterpret_cast<char*>(data_ptr)[new_length] = '\0';
}

// FUNCTION: IMPERIALISM 0x0049eb00
CString* AssignStringSharedRefAndReturnThis(CString* dest, const CString* src) {
  dest->StringSharedRef_AssignFromPtr(*src);
  return dest;
}

extern "C" unsigned char g_MbcsCharTypeTable_006A8018[512] = {0};
extern "C" int g_fMbcsEnabledForStringCompare_006A811C = 0;

undefined4 EnterIndexedCriticalSectionWithLazyInit(void);
undefined4 LeaveIndexedCriticalSection(void);

// FUNCTION: IMPERIALISM 0x005e7980
int CompareAnsiStringsWithMbcsAwareness(unsigned char* lhs, unsigned char* rhs) {
  if (g_fMbcsEnabledForStringCompare_006A811C != 0) {
    reinterpret_cast<void(__cdecl*)(int)>(EnterIndexedCriticalSectionWithLazyInit)(0x19);
    while (1) {
      unsigned short lhsUnit = (unsigned short)*lhs;
      unsigned char* lhsNext = lhs + 1;
      if ((g_MbcsCharTypeTable_006A8018[lhsUnit + 1] & 4) != 0) {
        unsigned char trailByte = *lhsNext;
        if (trailByte == 0) {
          lhsUnit = 0;
        } else {
          lhsNext = lhs + 2;
          lhsUnit = (unsigned short)(((unsigned short)*lhs << 8) | (unsigned short)trailByte);
        }
      }
      unsigned short rhsUnit = (unsigned short)*rhs;
      unsigned char* rhsNext = rhs + 1;
      if ((g_MbcsCharTypeTable_006A8018[rhsUnit + 1] & 4) != 0) {
        unsigned char trailByte = *rhsNext;
        if (trailByte == 0) {
          rhsUnit = 0;
        } else {
          rhsNext = rhs + 2;
          rhsUnit = (unsigned short)(((unsigned short)*rhs << 8) | (unsigned short)trailByte);
        }
      }
      if (lhsUnit != rhsUnit) {
        reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(0x19);
        return (int)((-(unsigned int)(rhsUnit < lhsUnit) & 2) - 1);
      }
      rhs = rhsNext;
      lhs = lhsNext;
      if (lhsUnit == 0) {
        reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(0x19);
        return 0;
      }
    }
  }

  while (1) {
    unsigned char lhsByte = *lhs;
    int lhsLess = (int)(lhsByte < *rhs);
    if (lhsByte != *rhs) {
      return (1 - (unsigned int)lhsLess) - (unsigned int)(lhsLess != 0);
    }
    if (lhsByte == 0) {
      return 0;
    }
    lhsByte = lhs[1];
    lhsLess = (int)(lhsByte < rhs[1]);
    if (lhsByte != rhs[1]) {
      return (1 - (unsigned int)lhsLess) - (unsigned int)(lhsLess != 0);
    }
    lhs = lhs + 2;
    rhs = rhs + 2;
    if (lhsByte == 0) {
      return 0;
    }
  }
}
