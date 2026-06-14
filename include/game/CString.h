#pragma once

#include "decomp_types.h"

struct SharedStringHeader {
  long ref_count;
  int text_length;
  int capacity;
};

class CString;

// Global operator+ helpers (own the original addresses). These are real
// __stdcall free functions: the destination is the hidden return slot (passed
// as the first stack argument, returned in EAX) and the callee cleans all three
// dwords (RET 0xc).
undefined** GetSharedEmptyStringRef(void);
void __stdcall DecrementSharedStringRefCountAndFree(long* ref_count_ptr);
CString* __stdcall AssignSharedStringConcatRefAndRef(CString* dst, const CString* lhs,
                                                     const CString* rhs);
CString* __stdcall AssignSharedStringConcatRefAndCStr(CString* dst, const CString* lhs,
                                                      const char* rhs_text);
CString* __stdcall AssignSharedStringConcatCStrAndRef(CString* dst, const char* lhs_text,
                                                      const CString* rhs);

class CString {
public:
  int data_ptr;

  CString();                                // 0x00605797 (init to the shared empty buffer)
  CString(const char* text_or_resource_id); // 0x00605950 (from C-string or low-word resource id)
  ~CString();                               // 0x006058e2
  undefined4 LoadResourceStringToSharedBuffer(unsigned int resource_id);
  void AllocateBufferForLength(int text_length);
  void EnsureCapacityOrAllocate(int required_capacity);
  void CopyBufferAndSetLength(int new_length, const char* src_text);
  CString* StringSharedRef_AssignFromPtr(const CString& src_ref);
  CString* AssignFromPtr(const CString& src_ref);
  CString* AssignFromRef(const CString& src_ref);
  CString* CopyFromCStr(const char* src_text);
  void ConcatenateBuffers(int lhs_len, const char* lhs_text, int rhs_len, const char* rhs_text);
  void EnsureUniqueSharedStringBuffer();
  void AssignConcatCStrAndRef(const char* lhs_text, const CString& rhs_ref);
  void AppendBuffer(int append_len, const char* append_text);
  CString* AppendSingleByte(char append_byte);   // 0x00605cf5 (operator+= one char)
  CString* AssignFromCStr(const char* text);     // 0x00605cce (operator+= C-string)
  CString* AssignFromSharedRef(const CString& src_ref); // 0x00605d0a (operator+= CString)
  int EnsureCapacityPreserveLength(int min_capacity);
  int EnsureCapacityAndSetLength(int new_length);
  void SetLengthAndTerminator(int new_length);
  SharedStringHeader* Header();
  const SharedStringHeader* Header() const;
  const char* Text() const;
  int Length() const;
  int Capacity() const;
};

CString* AssignStringSharedRefAndReturnThis(CString* dest, const CString* src);

int CompareAnsiStringsWithMbcsAwareness(unsigned char* lhs, unsigned char* rhs);
