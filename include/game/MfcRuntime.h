#pragma once

#include "decomp_types.h"

undefined4 GetOrCreateMfcModuleThreadState(void);
undefined4 FreeHeapBlockWithAllocatorTracking(void);

void BeginWaitCursor(void);
void EndWaitCursor(void);

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
