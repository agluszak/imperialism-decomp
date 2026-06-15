#pragma once

#include "compat.h"
#include "decomp_types.h"

// Retail MFC 4.2 from the MSVC500 toolchain (same nafxcw.lib the game linked).
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#include <afx.h>
#include <afxcoll.h>
#include <afxplex_.h>
#include <afxwin.h>

#ifdef CopyMemory
#undef CopyMemory
#endif
#ifdef MoveMemory
#undef MoveMemory
#endif

// MFC module-state heap bridges (MfcRuntime.cpp).
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 GetOrCreateMfcModuleThreadState(void);
undefined4 FreeHeapBlockWithAllocatorTracking(void);
