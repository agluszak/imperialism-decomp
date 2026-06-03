#pragma once

#include "decomp_types.h"

struct SharedStringHeader {
  long ref_count;
  int text_length;
  int capacity;
};

// Free functions that own original addresses (CString globals / operator+ /
// DDV helpers). The C-style explicit-pointer forwarder shims that used to sit
// here were unused and have been removed in favour of the StringShared methods.
undefined** GetSharedEmptyStringRef(void);
void __cdecl DecrementSharedStringRefCountAndFree(long* ref_count_ptr);
void AssignSharedStringConcatRefAndRef(int* dst_ref_ptr, int* lhs_ref_ptr, int* rhs_ref_ptr);
void __stdcall AssignSharedStringConcatRefAndCStr(int* dst_ref_ptr, int* lhs_ref_ptr,
                                                  const char* rhs_text);
void AssignSharedStringConcatCStrAndRef(int* dst_ref_ptr, const char* lhs_text, int* rhs_ref_ptr);
int __fastcall AppendSingleByteToSharedStringFromArg(int* ref_ptr, int unused_edx, int append_byte);
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr);

class StringShared {
public:
  int data_ptr;

  ~StringShared();
  StringShared* InitFromEmpty();
  undefined4 LoadResourceStringToSharedBuffer(unsigned int resource_id);
  void AllocateBufferForLength(int text_length);
  void EnsureCapacityOrAllocate(int required_capacity);
  StringShared* ConstructFromCStrOrResourceId(const char* text_or_resource_id);
  void CopyBufferAndSetLength(int new_length, const char* src_text);
  StringShared* StringSharedRef_AssignFromPtr(const StringShared& src_ref);
  StringShared* AssignFromPtr(const StringShared& src_ref);
  StringShared* AssignFromRef(const StringShared& src_ref);
  StringShared* CopyFromCStr(const char* src_text);
  void ConcatenateBuffers(int lhs_len, const char* lhs_text, int rhs_len, const char* rhs_text);
  void EnsureUniqueSharedStringBuffer();
  void AssignConcatRefAndRef(const StringShared& lhs_ref, const StringShared& rhs_ref);
  void AssignConcatRefAndCStr(const StringShared& lhs_ref, const char* rhs_text);
  void AssignConcatCStrAndRef(const char* lhs_text, const StringShared& rhs_ref);
  void AppendBuffer(int append_len, const char* append_text);
  undefined4 AssignFromCStr(const char* text);
  undefined4 AssignFromSharedRef(const StringShared& src_ref);
  int EnsureCapacityPreserveLength(int min_capacity);
  int EnsureCapacityAndSetLength(int new_length);
  void SetLengthAndTerminator(int new_length);
  SharedStringHeader* Header();
  const SharedStringHeader* Header() const;
  const char* Text() const;
  int Length() const;
  int Capacity() const;
};
