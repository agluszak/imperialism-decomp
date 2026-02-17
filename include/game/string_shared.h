#pragma once

#include "decomp_types.h"

#include <windows.h>

undefined **GetSharedEmptyStringRef(void);
int *InitializeSharedStringRefFromEmpty(int *dst_ref_ptr);
int *StringSharedRef_AssignFromPtr(int *dst_ref_ptr, int *src_ref_ptr);
void ReleaseSharedStringRefIfNotEmpty(int *ref_ptr);
int *ConstructSharedStringFromCStrOrResourceId(int *dst_ref_ptr, LPCSTR text_or_resource_id);
undefined4 AssignStringSharedFromCStr(undefined4 this_ptr, LPCSTR text);
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int *src_ref_ptr);

class StringShared {
public:
  int data_ptr;

  int *AssignFromPtr(int *dst_ref_ptr);
};
