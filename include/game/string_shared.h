#pragma once

#include "decomp_types.h"

#include <windows.h>

undefined** GetSharedEmptyStringRef(void);
int* InitializeSharedStringRefFromEmpty(int* dst_ref_ptr);
int* StringSharedRef_AssignFromPtr(int* dst_ref_ptr, int* src_ref_ptr);
void AllocateSharedStringBufferForLength(int* ref_ptr, int text_length);
void __cdecl DecrementSharedStringRefCountAndFree(LONG* ref_count_ptr);
void __fastcall EnsureUniqueSharedStringBuffer(int* ref_ptr);
void WrapperFor_AllocateSharedStringBufferForLength_At006058b9(int* ref_ptr, int required_capacity);
void ReleaseSharedStringRefIfNotEmpty(int* ref_ptr);
int* ConstructSharedStringFromCStrOrResourceId(int* dst_ref_ptr, LPCSTR text_or_resource_id);
void WrapperFor_CopyMemoryPossiblyOverlapping_At006059fc(int* ref_ptr, int new_length,
                                                         LPCSTR src_text);
int* WrapperFor_CopyMemoryPossiblyOverlapping_At00605a78(int* ref_ptr, LPCSTR src_text);
void ConcatenateTwoBuffersToSharedString(int* ref_ptr, int lhs_len, LPCSTR lhs_text, int rhs_len,
                                         LPCSTR rhs_text);
void AssignSharedStringConcatRefAndRef(int* dst_ref_ptr, int* lhs_ref_ptr, int* rhs_ref_ptr);
void AssignSharedStringConcatRefAndCStr(int* dst_ref_ptr, int* lhs_ref_ptr, LPCSTR rhs_text);
void AssignSharedStringConcatCStrAndRef(int* dst_ref_ptr, LPCSTR lhs_text, int* rhs_ref_ptr);
void AppendBufferToSharedString(int* ref_ptr, int append_len, LPCSTR append_text);
int __fastcall AppendSingleByteToSharedStringFromArg(int* ref_ptr, int unused_edx, int append_byte);
int EnsureSharedStringCapacityPreserveLength(int* ref_ptr, int min_capacity);
void SetSharedStringLengthAndTerminator(int* ref_ptr, int new_length);
int WrapperFor_EnsureSharedStringCapacityPreserveLength_At00605d99(int* ref_ptr, int new_length);
undefined4 AssignStringSharedFromCStr(undefined4 this_ptr, LPCSTR text);
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr);

class StringShared {
public:
  int data_ptr;

  int* AssignFromPtr(int* dst_ref_ptr);
};
