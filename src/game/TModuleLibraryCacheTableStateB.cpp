#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TObject.h"

// Shared empty-string literal at 0x006a13a0 (defined in global_data_tables.cpp).
extern "C" char g_szEmptyString[];
extern "C" const char s_BmpResourceNameFormat_006951C4[];

namespace {
// "A file required by the program, '%s,' is missing." (original .rdata at 0x00695188).
const char* const kMissingFileFormat = reinterpret_cast<const char*>(0x00695188);
} // namespace

// GLOBAL: IMPERIALISM 0x6a134c
extern "C" TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState = nullptr;

// Both embedded CMap members default-construct (hash size 17, block size 10); the leading
// m_field0 is zeroed first (declaration order), matching the original's [obj]=0 then map A,
// map B init sequence.
// FUNCTION: IMPERIALISM 0x00498f60
TModuleLibraryCacheTableStateB::TModuleLibraryCacheTableStateB() : m_field0(0) {
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
      delete reinterpret_cast<TObject*>(record->pObject);
    }
    m_tableB.RemoveKey(record);
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
    message.Format(kMissingFileFormat, path);
    AfxMessageBox(message, MB_OK, 0);
  }
  return m_slots[slot] != NULL;
}

// FUNCTION: IMPERIALISM 0x00499380
BOOL TModuleLibraryCacheTableStateB::LoadPrimaryDataLibraryWithErrorDialog(LPCSTR path) {
  m_primaryModule = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
  if (m_primaryModule == NULL) {
    CString message;
    message.Format(kMissingFileFormat, path);
    AfxMessageBox(message, MB_OK, 0);
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

// FUNCTION: IMPERIALISM 0x004997e0
void* TModuleLibraryCacheTableStateB::LoadBmpResourceByIdCached(unsigned short bmpId) {
  CString resourceName;
  resourceName.Format(s_BmpResourceNameFormat_006951C4, bmpId);

  for (int nameSlotIndex = 0; nameSlotIndex < 4; nameSlotIndex++) {
    HMODULE module = m_slots[nameSlotIndex];
    if (module == NULL) {
      continue;
    }
    HBITMAP bitmap = LoadBitmapA(module, resourceName);
    if (bitmap != NULL) {
      return reinterpret_cast<void*>(bitmap);
    }
  }

  for (int idSlotIndex = 0; idSlotIndex < 4; idSlotIndex++) {
    HMODULE module = m_slots[idSlotIndex];
    if (module == NULL) {
      continue;
    }
    HBITMAP bitmap = LoadBitmapA(module, MAKEINTRESOURCE(bmpId));
    if (bitmap != NULL) {
      return reinterpret_cast<void*>(bitmap);
    }
  }

  return NULL;
}

// FUNCTION: IMPERIALISM 0x0049a390
void TModuleLibraryCacheTableStateB::ReleaseRecordByHandle(void* handle) {
  CacheRecord* record = static_cast<CacheRecord*>(handle);
  if (record == NULL)
    return;

  CacheRecord* foundRecord = NULL;
  if (!m_tableB.Lookup(handle, foundRecord) || foundRecord != record) {
    foundRecord = NULL;
  }

  if (foundRecord != NULL) {
    record = foundRecord;
  }

  record->refCount--;
  if (record->refCount < 1) {
    if (record->pObject != NULL) {
      delete reinterpret_cast<TObject*>(record->pObject);
    }

    m_tableB.RemoveKey(record);
    m_tableA.RemoveKey(record->id);
    delete record;
  }
}
