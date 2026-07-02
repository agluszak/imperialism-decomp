#include "game/TModuleLibraryCacheTableStateB.h"

#include "game/global_data_tables.h"

extern "C" const char s_BmpResourceNameFormat_006951C4[];
extern "C" const char s_MissingRequiredFileFormat_00695188[];

// Both embedded CMap members default-construct (hash size 17, block size 10); the leading
// m_dibPalette is zeroed first (declaration order), matching the original's [obj]=0 then map A,
// map B init sequence.
// FUNCTION: IMPERIALISM 0x00498f60
TModuleLibraryCacheTableStateB::TModuleLibraryCacheTableStateB() : m_dibPalette(0) {
  m_primaryModule = 0;
  m_slots[0] = 0;
  m_slots[1] = 0;
  m_slots[2] = 0;
  m_slots[3] = 0;
}

// FUNCTION: IMPERIALISM 0x00498fe0
TModuleLibraryCacheTableStateB::~TModuleLibraryCacheTableStateB() {
  while (m_tableA.GetCount() > 0) {
    POSITION pos = m_tableA.GetStartPosition();
    WORD key;
    CacheRecord* record;
    m_tableA.GetNextAssoc(pos, key, record);

    if (record->pObject != NULL) {
      delete record->pObject;
    }
    m_tableB.RemoveKey(record->pObject);
    m_tableA.RemoveKey(key);
    delete record;
  }

  for (int i = 0; i < 4; ++i) {
    if (m_slots[i] != NULL) {
      FreeLibrary(m_slots[i]);
      m_slots[i] = NULL;
    }
  }

  if (m_primaryModule != NULL) {
    FreeLibrary(m_primaryModule);
    m_primaryModule = NULL;
  }
}

// Compiler-emitted destructors for the two embedded CMap<> members above (m_tableA,
// m_tableB); MSVC500 instantiates and calls these automatically as part of
// ~TModuleLibraryCacheTableStateB(), so there is no source body to write (mfc-collections
// skill: "let MSVC instantiate them from the real member type"). bd 1uj.44 (junk-named
// non-RTTI state classes): these previously carried invented vtable-address-suffixed
// placeholder class names (TModuleLibraryCacheTableStateA_0064BA68 /
// TModuleLibraryCacheTableStateB_0064BA80) with hand-written stub bodies.
// TEMPLATE: IMPERIALISM 0x0049ae30
// ??1?$CMap@GGPAUCacheRecord@@PAU1@@@UAE@XZ

// TEMPLATE: IMPERIALISM 0x0049b270
// ??1?$CMap@PAXPAXPAUCacheRecord@@PAU1@@@UAE@XZ

// FUNCTION: IMPERIALISM 0x004992a0
BOOL TModuleLibraryCacheTableStateB::LoadModuleLibrarySlotWithErrorDialog(LPCSTR path, int slot) {
  if (m_slots[slot] != NULL) {
    FreeLibrary(m_slots[slot]);
    m_slots[slot] = NULL;
  }
  m_slots[slot] = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
  if (m_slots[slot] == NULL) {
    // The original inlines the error path here; the local CString is what gives this
    // function its SEH frame.
    CString message;
    message.Format(s_MissingRequiredFileFormat_00695188, static_cast<LPCTSTR>(path));
    AfxMessageBox(static_cast<LPCTSTR>(message), MB_OK, 0);
  }
  return m_slots[slot] != NULL;
}

// FUNCTION: IMPERIALISM 0x00499380
BOOL TModuleLibraryCacheTableStateB::LoadPrimaryDataLibraryWithErrorDialog(const CString& path) {
  m_primaryModule = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
  if (m_primaryModule == NULL) {
    CString message;
    message.Format(s_MissingRequiredFileFormat_00695188, static_cast<LPCTSTR>(path));
    AfxMessageBox(static_cast<LPCTSTR>(message), MB_OK, 0);
  }
  return m_primaryModule != NULL;
}

// Loads a localized UI string by (group, index) into *out using resource id
// (group * 100 + index) from the primary data module. On load failure falls back to the
// shared empty string. Resource id = group*100 + index matches LoadStringA's id arithmetic.
// FUNCTION: IMPERIALISM 0x004994c0
void TModuleLibraryCacheTableStateB::LoadUiStringResourceByGroupAndIndex(CString* out, int group,
                                                                         int index) {
  LPSTR buffer = out->GetBufferSetLength(0x100);
  int length = LoadStringA(m_primaryModule, index + group * 100, buffer, 0x100);
  out->ReleaseBuffer(length);
  if (length == 0) {
    CString empty(g_szEmptyString);
    *out = empty;
  }
}

// FUNCTION: IMPERIALISM 0x004995c0
CDibPal* TModuleLibraryCacheTableStateB::EnsureDefaultDibPalette() {
  if (m_dibPalette == NULL) {
    CDib* paletteDib = LoadBmpResourceByIdCached(0x3b6);
    m_dibPalette = new CDibPal();
    if (m_dibPalette != NULL && paletteDib != NULL) {
      m_dibPalette->BuildPaletteFromBitmapColorTable(paletteDib);
    }
    ReleaseRecordById(0x3b6);
  }

  return m_dibPalette;
}

// FUNCTION: IMPERIALISM 0x004997e0
CDib* TModuleLibraryCacheTableStateB::LoadBmpResourceByIdCached(unsigned short bmpId) {
  CacheRecord* record = NULL;
  if (m_tableA.Lookup(bmpId, record)) {
    record->refCount++;
    return static_cast<CDib*>(record->pObject);
  }

  CString resourceName;
  resourceName.Format(s_BmpResourceNameFormat_006951C4, bmpId);
  CDib* dib = new CDib();
  if (dib == NULL) {
    return NULL;
  }

  for (int nameSlotIndex = 0; nameSlotIndex < 4; nameSlotIndex++) {
    HMODULE module = m_slots[nameSlotIndex];
    if (module == NULL) {
      continue;
    }
    if (dib->LoadBitmapResourceAndInitializeSurfaceState(resourceName, module)) {
      record = new CacheRecord;
      record->id = static_cast<short>(bmpId);
      record->pObject = dib;
      record->refCount = 1;
      m_tableA.SetAt(bmpId, record);
      m_tableB.SetAt(dib, record);
      return dib;
    }
  }

  for (int idSlotIndex = 0; idSlotIndex < 4; idSlotIndex++) {
    HMODULE module = m_slots[idSlotIndex];
    if (module == NULL) {
      continue;
    }
    if (dib->LoadBitmapResourceAndInitializeSurfaceState(MAKEINTRESOURCE(bmpId), module)) {
      record = new CacheRecord;
      record->id = static_cast<short>(bmpId);
      record->pObject = dib;
      record->refCount = 1;
      m_tableA.SetAt(bmpId, record);
      m_tableB.SetAt(dib, record);
      return dib;
    }
  }

  delete dib;
  return NULL;
}

// FUNCTION: IMPERIALISM 0x00499b40
CDib* TModuleLibraryCacheTableStateB::BuildIndexedBmpResourceById(short bmpId, int width,
                                                                  int height, int patternMode) {
  CDib* dib = new CDib(width, height, 8);
  if (dib == NULL) {
    return NULL;
  }

  if (m_dibPalette == NULL) {
    CDib* paletteDib = LoadBmpResourceByIdCached(0x3b6);
    m_dibPalette = new CDibPal();
    if (m_dibPalette != NULL && paletteDib != NULL) {
      m_dibPalette->BuildPaletteFromBitmapColorTable(paletteDib);
    }
    if (paletteDib != NULL) {
      ReleaseRecordByHandle(paletteDib);
    }
  }

  if (m_dibPalette != NULL && m_dibPalette->m_pLogPalette != NULL) {
    dib->CopyRgbQuadTableFrom(m_dibPalette->m_pLogPalette);
  }
  dib->EnsureDibSectionCreated(NULL);

  unsigned int remaining = static_cast<unsigned int>(dib->m_pixelBytes);
  unsigned char* dest = static_cast<unsigned char*>(dib->m_dibBits);
  unsigned char value = 0;
  if (patternMode == 0) {
    while (remaining != 0) {
      *dest++ = value++;
      remaining--;
    }
  } else {
    while (remaining != 0) {
      remaining--;
      if (((remaining & 4) == 0) || ((remaining & 10) == 0)) {
        *dest = 0x10;
      } else {
        *dest = value++;
      }
      dest++;
    }
  }

  CacheRecord* record = NULL;
  if (m_tableA.Lookup(static_cast<WORD>(bmpId), record)) {
    record->refCount++;
  } else {
    record = new CacheRecord;
    record->id = bmpId;
    record->pObject = dib;
    record->refCount = 1;
    m_tableA.SetAt(static_cast<WORD>(bmpId), record);
    m_tableB.SetAt(dib, record);
  }

  return dib;
}

// FUNCTION: IMPERIALISM 0x0049a190
void TModuleLibraryCacheTableStateB::ReleaseRecordById(short id) {
  CacheRecord* record = NULL;
  m_tableA.Lookup(static_cast<WORD>(id), record);

  record->refCount--;
  if (record->refCount < 1) {
    if (record->pObject != NULL) {
      delete record->pObject;
    }

    m_tableB.RemoveKey(record->pObject);
    m_tableA.RemoveKey(record->id);
    delete record;
  }
}

// FUNCTION: IMPERIALISM 0x0049a390
void TModuleLibraryCacheTableStateB::ReleaseRecordByHandle(void* handle) {
  if (handle == NULL) {
    return;
  }

  CacheRecord* record = NULL;
  if (!m_tableB.Lookup(handle, record)) {
    record = static_cast<CacheRecord*>(handle);
  }

  record->refCount--;
  if (record->refCount < 1) {
    if (record->pObject != NULL) {
      delete record->pObject;
    }

    m_tableB.RemoveKey(record->pObject);
    m_tableA.RemoveKey(record->id);
    delete record;
  }
}
