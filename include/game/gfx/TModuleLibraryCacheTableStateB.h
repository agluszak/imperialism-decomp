#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
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
// distinct vtables (0x0064ba80 / 0x0064ba68), i.e. two distinct instantiations. The
// resource lookup/insert sites have not yet identified the exact scalar key/value types;
// this distinction affects the per-instantiation vtable but not the recovered layout.
//
// bd 1uj.44: these two CMap<> destructors are compiler-emitted (no hand-written body is
// correct per the mfc-collections skill) at 0x0049ae30 (CMap<short,short,CacheRecord*,
// CacheRecord*>::~CMap, vtable 0x0064ba80) and 0x0049b270 (CMap<void*,void*,CacheRecord*,
// CacheRecord*>::~CMap, vtable 0x0064ba68) — claimed via `// TEMPLATE:` markers in
// TModuleLibraryCacheTableStateB.cpp (see the ISLE-style decorated-name-comment
// convention). They previously carried invented vtable-address-suffixed placeholder
// class names (TModuleLibraryCacheTableStateA_0064BA68 / TModuleLibraryCacheTableStateB_
// 0064BA80) with hand-written stub bodies; both are retired in favor of letting the real
// `CMap<K,ARG_K,V,ARG_V>` members below emit their own destructors.
struct CacheRecord {
  // NOOP: verified empty in original allocation sites, including 0x00499ed0.
  CacheRecord() {}
  CacheRecord(short idValue, CObject* objectValue)
      : id(idValue), pObject(objectValue), refCount(1) {}

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
  // Bump the reference count for a registered object handle. 0x0049a120
  void IncrementRecordRefCountByHandle(void* handle);
  // Bump the reference count for a registered dialog-resource identifier. 0x0049a0b0
  void IncrementRecordRefCountById(short id);

  // Load a localized UI string by (group, index) into `out`. Reached via the global
  // g_pModuleLibraryCacheState from many call sites (e.g. TMultiplayerMgr init, low-disk
  // warning). Real __thiscall method (ECX = this on entry at 0x4994c0).
  int LoadUiStringResourceByGroupAndIndex(CString* out, int group, int index);        // 0x004994c0
  CString LoadLocalizedStringByPackedGroupAndIndex(unsigned int packedGroupAndIndex); // 0x0049a590
  CString LoadLocalizedStringByGroupAndIndex(int group, int index);                   // 0x0049a6c0

  // Load a localized UI string by raw resource id into `out` (falls back to the shared
  // empty string). Reached via ILT 0x406933; sibling of the (group, index) loader.
  int LoadUiStringResourceById(CString* out, unsigned int stringId); // 0x00499440

  // Cached bitmap-surface lookup/load by resource id (primary + slot modules). 0x004997e0
  CDib* LoadBmpResourceByIdCached(short bmpId);

  // Lazily build and return the shared palette from backdrop bitmap 0x3b6. 0x004995c0
  CDibPal* EnsureDefaultDibPalette();

  // Convert a PALETTEINDEX color through the shared DIB palette to PALETTERGB; leave
  // literal COLORREF values unchanged. 0x0049ace0
  COLORREF ResolvePaletteIndexColor(unsigned int packedColor);

  // Resolve the shared default LOGPALETTE build buffer:
  // EnsureDefaultDibPalette()->m_pLogPalette. Real __thiscall at 0x004995a0 (Ghidra's
  // "TMacViewMgr::WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At004995a0"; the
  // ECX receiver is really this cache, not a TMacViewMgr). Used when seeding a new CDib's
  // color table.
  LOGPALETTE* ResolveDefaultLogPalette(); // 0x004995a0

  // Build an indexed 8-bit CDib fallback and cache it by resource id. 0x00499b40
  CDib* BuildIndexedBmpResourceById(short bmpId, int width, int height, int patternMode);

  // Retain the record already indexed by id, or register object in both cache maps.
  // This retail-only helper currently has no direct call xrefs. 0x00499e80
  void RetainOrRegisterObject(short id, CObject* object);
  // ResourceMgr.cpp palette-resource overloads. The numeric form accepts either a
  // 16-bit MAKEINTRESOURCE id or formats a larger id as "#<decimal>".
  BOOL LoadPaletteResourceByName(CPalette* palette, LPCSTR resourceName); // 0x0049aac0
  BOOL LoadPaletteResource(CPalette* palette, unsigned long resourceId);  // 0x0049abd0

  // Retail-only empty cache hook reached by a dead global wrapper. 0x00499280
  void NoOpRetailCacheHook();

  CDibPal* m_dibPalette;                                   // 0x00 global DIB palette companion
  CMap<short, short, CacheRecord*, CacheRecord*> m_tableA; // 0x04 (vtable 0x0064ba80)
  CMap<void*, void*, CacheRecord*, CacheRecord*> m_tableB; // 0x20 (vtable 0x0064ba68)
  HMODULE m_slots[4];                                      // 0x3c (gob pack slots 0..3)
  HMODULE m_primaryModule;                                 // 0x4c
};

// g_pModuleLibraryCacheState is declared in game/global_data_tables.h (single
// authoritative declaration; the extern "C" copy here had drifted in linkage).
