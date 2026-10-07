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

// Retail MFC operator new/delete (0x606f73/0x606faf) are LIBRARY markers in src/game/mfc_heap_library.cpp.

// CString helper functions
