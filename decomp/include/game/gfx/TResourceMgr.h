#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/mfc.h"
#include <afxtempl.h>

struct CacheRecord {
  // NOOP: verified empty in original allocation sites, including 0x00499ed0.
  CacheRecord() {}
  CacheRecord(short idValue, CObject* objectValue)
      : id(idValue), pObject(objectValue), refCount(1) {}

  short id;
  CObject* pObject;
  int refCount;
};

class TResourceMgr {
public:
  TResourceMgr();
  ~TResourceMgr();

  BOOL LoadModuleLibrarySlotWithErrorDialog(LPCSTR path, int slot);
  // Load the primary data library into the dedicated +0x4c slot
  BOOL LoadPrimaryDataLibraryWithErrorDialog(const CString& path);

  void ReleaseRecordById(short id);
  void ReleaseRecordByHandle(void* handle);
  // Bump the reference count for a registered object handle
  void IncrementRecordRefCountByHandle(void* handle);
  // Bump the reference count for a registered dialog-resource identifier
  void IncrementRecordRefCountById(short id);

  int LoadUiStringResourceByGroupAndIndex(CString* out, int group, int index);
  CString LoadPackedString(unsigned int packedGroupAndIndex);
  CString LoadLocalizedStringByGroupAndIndex(int group, int index);

  int LoadUiStringResourceById(CString* out, unsigned int stringId);

  // Cached bitmap-surface lookup/load by resource id (primary + slot modules)
  CDib* LoadBmpResourceByIdCached(short bmpId);

  // Lazily build and return the shared palette from backdrop bitmap 0x3b6
  CDibPal* EnsureDefaultDibPalette();

  COLORREF ResolvePaletteIndexColor(unsigned int packedColor);

  LOGPALETTE* ResolveDefaultLogPalette();

  // Build an indexed 8-bit CDib fallback and cache it by resource id
  CDib* BuildIndexedBmpResourceById(short bmpId, int width, int height, int patternMode);

  void RetainOrRegisterObject(short id, CObject* object);
  BOOL LoadPaletteResourceByName(CPalette* palette, LPCSTR resourceName);
  BOOL LoadPaletteResource(CPalette* palette, unsigned long resourceId);

  // Retail-only empty cache hook reached by a dead global wrapper
  void NoOpRetailCacheHook();

  CDibPal* m_dibPalette; // global DIB palette companion
  CMap<short, short, CacheRecord*, CacheRecord*> m_recordsByResourceId;
  CMap<void*, void*, CacheRecord*, CacheRecord*> m_recordsByObject;
  HMODULE m_slots[4];
  HMODULE m_primaryModule;
};
