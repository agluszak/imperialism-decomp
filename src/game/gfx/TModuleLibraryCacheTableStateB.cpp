#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include <new.h>
#include <ctype.h>
// The retail body emits `CALL _isdigit`; undo the <ctype.h> macro so the function-call
// form is used (the macro would inline the __pctype test and drop the call).
#undef isdigit

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

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
    short key;
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
// FUNCTION: IMPERIALISM 0x00499440
int TModuleLibraryCacheTableStateB::LoadUiStringResourceById(CString* out, unsigned int stringId) {
  LPSTR buffer = out->GetBuffer(0x1000);
  int length = LoadStringA(m_primaryModule, stringId, buffer, 0x1000);
  if (length == 0) {
    out->ReleaseBuffer(-1);
    *out = g_szEmptyString;
    return 1;
  }
  out->ReleaseBuffer(-1);
  return 1;
}

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

// FUNCTION: IMPERIALISM 0x004995a0
LOGPALETTE* TModuleLibraryCacheTableStateB::ResolveDefaultLogPalette() {
  return EnsureDefaultDibPalette()->m_pLogPalette;
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
CDib* TModuleLibraryCacheTableStateB::LoadBmpResourceByIdCached(short bmpId) {
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
  if (m_tableA.Lookup(bmpId, record)) {
    record->refCount++;
  } else {
    record = new CacheRecord;
    record->id = bmpId;
    record->pObject = dib;
    record->refCount = 1;
    m_tableA.SetAt(bmpId, record);
    m_tableB.SetAt(dib, record);
  }

  return dib;
}

// Increment the ref count of the m_tableA record whose key is the low 16 bits of
// packedKey; if no such record is registered (e.g. a picture record that was never
// stored under this table), treat packedKey itself as an already-valid CacheRecord*
// and bump its ref count directly. Faithful to the original's manually-inlined hash
// walk, expressed via the public CMap API (mfc-collections: never walk protected
// CMap internals).
//
// UNRESOLVED_FIELD_ATTRIBUTION: the parameter's width does not agree across the ABI
// boundary. This body reads `word ptr [ESP+8]` for the lookup but `dword ptr [ESP+8]`
// as a CacheRecord* on the miss path, while all three call sites push only 16 bits and
// leave the high half as whatever happened to be in the register: 0x48f080
// `MOV AX,CX` over EAX=cachedBitmap, 0x48f640 `MOV AX,DX` over EAX=[this+0x88],
// 0x48f190 `MOV SI,CX` over ESI=this. The likeliest reading is an original ODR
// mismatch (the caller TU declared a 16-bit id parameter, this TU defined a pointer
// parameter); until that is proved, the call sites pass the plain short id and the
// miss path stays modelled as the pointer read it compiles to.
// FUNCTION: IMPERIALISM 0x0049a0b0
void TModuleLibraryCacheTableStateB::IncrementDialogResourceRefCountByShortIdInRegistry(
    unsigned int packedKey) {
  CacheRecord* record = NULL;
  if (m_tableA.Lookup(static_cast<short>(packedKey), record)) {
    record->refCount++;
  } else {
    reinterpret_cast<CacheRecord*>(packedKey)->refCount++;
  }
}

// FUNCTION: IMPERIALISM 0x0049a190
void TModuleLibraryCacheTableStateB::ReleaseRecordById(short id) {
  CacheRecord* record = NULL;
  m_tableA.Lookup(id, record);

  record->refCount--;
  if (record->refCount <= 0) {
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
  if (record->refCount <= 0) {
    if (record->pObject != NULL) {
      delete record->pObject;
    }

    m_tableB.RemoveKey(record->pObject);
    m_tableA.RemoveKey(record->id);
    delete record;
  }
}

// FUNCTION: IMPERIALISM 0x0049a590
CString TModuleLibraryCacheTableStateB::LoadLocalizedStringByPackedGroupAndIndex(
    unsigned int packedGroupAndIndex) {
  CString result;
  char* buffer = result.GetBuffer(0x100);
  int group = packedGroupAndIndex >> 8;
  int index = packedGroupAndIndex & 0xff;
  if (LoadStringA(m_primaryModule, group * 100 + index, buffer, 0x100) == 0) {
    result.ReleaseBuffer(-1);
    result = g_szEmptyString;
  } else {
    result.ReleaseBuffer(-1);
  }
  return result;
}

// Ghidra attributed this to TToolBarCluster, but the +0x4c receiver field is the module
// cache's m_primaryModule and matches the packed-argument sibling immediately above.
// FUNCTION: IMPERIALISM 0x0049a6c0
CString TModuleLibraryCacheTableStateB::LoadLocalizedStringByGroupAndIndex(int group, int index) {
  CString result;
  char* buffer = result.GetBuffer(0x100);
  if (LoadStringA(m_primaryModule, group * 100 + index, buffer, 0x100) == 0) {
    result.ReleaseBuffer(-1);
    result = g_szEmptyString;
  } else {
    result.ReleaseBuffer(-1);
  }
  return result;
}

// Loads a localized template string by packed group/index from `cache`, then expands each
// `[N]` escape (N a single ASCII digit) by resolving the N-th trailing packed-id argument
// (counting from `templateId`: [0] = templateId, [1] = first vararg) through the same cache
// and appending the localized result. Non-digit bracket groups are skipped through ']'.
// FUNCTION: IMPERIALISM 0x0049a910
CString* renderTemplateOrExpandTokens(TModuleLibraryCacheTableStateB* cache, CString* out,
                                      unsigned int templateId, ...) {
  CString result;
  CString templateText = cache->LoadLocalizedStringByPackedGroupAndIndex(templateId);
  char* t = (char*)(LPCSTR)templateText;
  int i = 0;
  char c;
  if (t[0] != '\0') {
    do {
      c = t[i];
      if (c == '[') {
        while (c != '\0') {
          int d = t[i + 1];
          i++;
          if (isdigit(d)) {
            result += cache->LoadLocalizedStringByPackedGroupAndIndex((&templateId)[t[i] - '0']);
            break;
          }
          c = t[i];
          if (c == ']') {
            break;
          }
        }
        c = t[i];
        while (c != ']' && c != '\0') {
          c = t[i + 1];
          i++;
        }
      } else {
        result += c;
      }
      c = t[i + 1];
      i++;
    } while (c != '\0');
  }
  new (out) CString(result);
  return out;
}

// Windows COLORREF values with the PALETTEINDEX marker (0x01 in the high byte) name an
// entry in the shared DIB palette. Native edit controls need an RGB-bearing palette color,
// so resolve that entry and return PALETTERGB; ordinary COLORREF values pass through.
// FUNCTION: IMPERIALISM 0x0049ace0
COLORREF TModuleLibraryCacheTableStateB::ResolvePaletteIndexColor(unsigned int packedColor) {
  if (m_dibPalette != NULL && (packedColor & 0xff000000) == 0x01000000) {
    PALETTEENTRY& entry = m_dibPalette->m_pLogPalette->palPalEntry[packedColor & 0xffff];
    return PALETTERGB(entry.peRed, entry.peGreen, entry.peBlue);
  }
  return packedColor;
}

// Compiler-emitted destructors for the two embedded CMap<> members above (m_tableA,
// m_tableB); MSVC500 instantiates and calls these automatically as part of
// ~TModuleLibraryCacheTableStateB(), so there is no source body to write (mfc-collections
// skill: "let MSVC instantiate them from the real member type"). bd 1uj.44 (junk-named
// non-RTTI state classes): these previously carried invented vtable-address-suffixed
// placeholder class names (TModuleLibraryCacheTableStateA_0064BA68 /
// TModuleLibraryCacheTableStateB_0064BA80) with hand-written stub bodies.
// TEMPLATE: IMPERIALISM 0x0049ae30
// ??1?$CMap@FFPAUCacheRecord@@PAU1@@@UAE@XZ

// VC5 emits afxtempl.h's archive loop for the short-key cache specialization. The body
// serializes each two-byte key and four-byte CacheRecord pointer, and rebuilds the map
// through CMap::SetAt while loading.
// TEMPLATE: IMPERIALISM 0x0049aef0
// ?Serialize@?$CMap@FFPAUCacheRecord@@PAU1@@@UAEXAAVCArchive@@@Z

// VC5 afxtempl.h body for the pointer-key m_tableB member.
// TEMPLATE: IMPERIALISM 0x0049b190
// ?RemoveKey@?$CMap@PAXPAXPAUCacheRecord@@PAU1@@@QAEHPAX@Z
template BOOL CMap<void*, void*, CacheRecord*, CacheRecord*>::RemoveKey(void*);

// TEMPLATE: IMPERIALISM 0x0049b270
// ??1?$CMap@PAXPAXPAUCacheRecord@@PAU1@@@UAE@XZ

// The pointer-key cache uses the same VC5 afxtempl.h archive loop, with four-byte key
// and value elements.
// TEMPLATE: IMPERIALISM 0x0049b330
// ?Serialize@?$CMap@PAXPAXPAUCacheRecord@@PAU1@@@UAEXAAVCArchive@@@Z

// VC5 afxtempl.h CPlex teardown for the short-key m_tableA member.
// TEMPLATE: IMPERIALISM 0x0049b630
// ?RemoveAll@?$CMap@FFPAUCacheRecord@@PAU1@@@QAEXXZ

// VC5 emits afxtempl.h's InitHashTable body for each embedded CMap specialization.
// These are MFC template code, not game-owned resize helpers.
// TEMPLATE: IMPERIALISM 0x0049b6a0
// ?InitHashTable@?$CMap@FFPAUCacheRecord@@PAU1@@@QAEXIH@Z

// TEMPLATE: IMPERIALISM 0x0049b7f0
// ?InitHashTable@?$CMap@PAXPAXPAUCacheRecord@@PAU1@@@QAEXIH@Z
