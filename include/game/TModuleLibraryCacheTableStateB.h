#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/mfc.h"
#include <afxtempl.h>

// Asset-pack cache. Loads .gob data packs as Windows DLL datafiles
// (LoadLibraryExA(..., LOAD_LIBRARY_AS_DATAFILE)) into per-slot HMODULE handles; resources
// are then pulled via the Win32 resource API. The global instance is
// g_pModuleLibraryCacheState (0x006a134c). Constructed at 0x00498f60; destroyed (with
// FreeLibrary on every slot) at 0x00498fe0.
//
// The two embedded tables at +0x04 / +0x20 are MFC CMap template specializations (NOT the
// concrete CMapStringToPtr/CMapPtrToPtr classes): their vtable slot 0 is the *inherited*
// CObject::GetRuntimeClass (0x00606fba), they default-construct with hash size 17 / block
// size 10 (the CMap defaults), and their destructors free the hash buffer + CPlex chain with
// no per-element key/value destruction — so both key and value are scalar. The two have
// distinct vtables (0x0064ba80 / 0x0064ba68), i.e. two distinct instantiations; the exact
// scalar key/value types (which fix the per-instantiation vtable but not the layout) are
// still provisional pending the resource lookup/insert sites.
struct CacheRecord {
  short id;
  CObject* pObject;
  int refCount;
};

class TModuleLibraryCacheTableStateB {
public:
  TModuleLibraryCacheTableStateB();
  ~TModuleLibraryCacheTableStateB(); // 0x00498fe0

  // Load a required .gob pack as a DLL datafile into slot `slot` (0..3), freeing any
  // previous handle first; shows the missing-file dialog on failure. Returns nonzero if
  // the resulting slot handle is valid.
  BOOL LoadModuleLibrarySlotWithErrorDialog(LPCSTR path, int slot); // 0x004992a0
  // Load the primary data library into the dedicated +0x4c slot.      0x00499380
  BOOL LoadPrimaryDataLibraryWithErrorDialog(const CString& path);

  void ReleaseRecordById(short id);         // 0x0049a190
  void ReleaseRecordByHandle(void* handle); // 0x0049a390

  // Load a localized UI string by (group, index) into `out`. Reached via the global
  // g_pModuleLibraryCacheState from many call sites (e.g. TMultiplayerMgr init, low-disk
  // warning). Real __thiscall method (ECX = this on entry at 0x4994c0).
  void LoadUiStringResourceByGroupAndIndex(CString* out, int group, int index); // 0x004994c0

  // Cached bitmap-surface lookup/load by resource id (primary + slot modules). 0x004997e0
  CDib* LoadBmpResourceByIdCached(unsigned short bmpId);

  // Lazily build and return the shared palette from backdrop bitmap 0x3b6. 0x004995c0
  CDibPal* EnsureDefaultDibPalette();

  // Build an indexed 8-bit CDib fallback and cache it by resource id. 0x00499b40
  CDib* BuildIndexedBmpResourceById(short bmpId, int width, int height, int patternMode);

  CDibPal* m_dibPalette;                                   // 0x00 global DIB palette companion
  CMap<WORD, WORD, CacheRecord*, CacheRecord*> m_tableA;   // 0x04 (vtable 0x0064ba80)
  CMap<void*, void*, CacheRecord*, CacheRecord*> m_tableB; // 0x20 (vtable 0x0064ba68)
  HMODULE m_slots[4];                                      // 0x3c (gob pack slots 0..3)
  HMODULE m_primaryModule;                                 // 0x4c
};

extern "C" TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;
