#include "game/CDC.h"
#include "game/CMapPtrToPtr.h"
#include "decomp_types.h"

undefined4 afxMapHDC(void);
extern "C" int __stdcall DeleteDC(void* hdc);

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00612682
CDC::CDC() : CObject(), m_hDC(0), m_hAttribDC(0), m_pHandleMapEntry(0), m_hWnd(0) {}

void CDC::CdcSlot14OnAttach(int hdc) {
  (void)hdc;
}

void CDC::CdcSlot18Stub() {}

void CDC::CdcSlot1cOnDetach() {}

// FUNCTION: IMPERIALISM 0x0061274c
bool CDC::AttachOutput(int hdc) {
  if (hdc == 0) {
    return false;
  }
  CMapPtrToPtr* hdcMap =
      reinterpret_cast<CMapPtrToPtr*>(reinterpret_cast<void*(__cdecl*)()>(reinterpret_cast<void(*)()>(afxMapHDC))());
  m_hDC = hdc;
  m_hAttribDC = hdc;
  void** valueSlot = hdcMap->GetOrCreateValueSlot(reinterpret_cast<void*>(hdc));
  *valueSlot = this;
  CdcSlot14OnAttach(hdc);
  return hdc != 0;
}

// FUNCTION: IMPERIALISM 0x00612783
void CDC::DetachOutput() {
  if (m_hDC != 0) {
    CMapPtrToPtr* hdcMap =
      reinterpret_cast<CMapPtrToPtr*>(reinterpret_cast<void*(__cdecl*)()>(reinterpret_cast<void(*)()>(afxMapHDC))());
    if (hdcMap != 0) {
      hdcMap->RemoveKey(reinterpret_cast<void*>(m_hDC));
    }
    CdcSlot1cOnDetach();
    m_hDC = 0;
  }
}

// FUNCTION: IMPERIALISM 0x006127ca
CDC::~CDC() {
  if (m_hDC != 0) {
    DetachOutput();
    DeleteDC(reinterpret_cast<void*>(m_hDC));
  }
}
