#include "game/list_box.h"

// MFC DDX_LBString / DDX_LBStringExact. Ghidra invented receiver classes
// (ListBoxControlWindowResolver / ListBoxSharedStringRef) for these; the real
// receivers are CDataExchange (the DDX cursor) and CString (our CString class).
//
// CString::Empty (0x60586d) is linked from nafxcw.lib. CDataExchange::PrepareCtrl
// (0x6189dc) is not yet ported, so it goes through a __fastcall ABI bridge.

undefined4 PrepareCtrl(void);

namespace {

// CDataExchange::PrepareCtrl(nIDC) -> HWND of the control (thiscall).
inline HWND PrepareDdxControl(CDataExchange* pDX, undefined4 nIDC) {
  return reinterpret_cast<HWND(__fastcall*)(CDataExchange*, int, undefined4)>(
      reinterpret_cast<void(*)()>(::PrepareCtrl))(pDX, 0, nIDC);
}

} // namespace

// FUNCTION: IMPERIALISM 0x00618df2
void __stdcall DDX_LBString(CDataExchange* pDX, undefined4 nIDC, CString* value) {
  HWND listbox = PrepareDdxControl(pDX, nIDC);
  if (pDX->m_bSaveAndValidate == 0) {
    SendMessageA(listbox, 0x18c, static_cast<WPARAM>(0xffffffff),
                 reinterpret_cast<LPARAM>(static_cast<LPCSTR>(*value)));
  } else {
    WPARAM selection = SendMessageA(listbox, 0x188, 0, 0);
    if (selection == static_cast<WPARAM>(0xffffffff)) {
      value->Empty();
    } else {
      LRESULT rawItemData = SendMessageA(listbox, 0x18a, selection, 0);
      LPARAM normalized = reinterpret_cast<LPARAM>(
          value->GetBufferSetLength(static_cast<int>(rawItemData)));
      SendMessageA(listbox, 0x189, selection, normalized);
    }
    value->ReleaseBuffer(static_cast<int>(0xffffffff));
  }
}

// FUNCTION: IMPERIALISM 0x00618e72
void __stdcall DDX_LBStringExact(CDataExchange* pDX, undefined4 nIDC, CString* value) {
  HWND target = PrepareDdxControl(pDX, nIDC);
  if (pDX->m_bSaveAndValidate == 0) {
    WPARAM index = SendMessageA(target, 0x1a2, static_cast<WPARAM>(0xffffffff),
                                reinterpret_cast<LPARAM>(static_cast<LPCSTR>(*value)));
    if (index != static_cast<WPARAM>(0xffffffff)) {
      SendMessageA(target, 0x186, index, 0);
    }
  } else {
    DDX_LBString(pDX, nIDC, value);
  }
}
