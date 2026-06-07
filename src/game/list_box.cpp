#include "game/list_box.h"

// MFC DDX_LBString / DDX_LBStringExact. Ghidra invented receiver classes
// (ListBoxControlWindowResolver / ListBoxSharedStringRef) for these; the real
// receivers are CDataExchange (the DDX cursor) and CString (our CString class).
//
// CString::GetBufferSetLength (0x605d99) and CString::ReleaseBuffer (0x605d71)
// are the already-ported CString methods EnsureCapacityAndSetLength /
// SetLengthAndTerminator and are called directly. CDataExchange::PrepareCtrl
// (0x6189dc) and CString::Empty (0x60586d) are not yet ported, so they go
// through __fastcall ABI bridges kept out of the function bodies.

undefined4 PrepareCtrl(void);
undefined4 Empty(void);

namespace {

// CDataExchange::PrepareCtrl(nIDC) -> HWND of the control (thiscall).
inline HWND PrepareDdxControl(CDataExchange* pDX, undefined4 nIDC) {
  return reinterpret_cast<HWND(__fastcall*)(CDataExchange*, int, undefined4)>(::PrepareCtrl)(pDX, 0,
                                                                                             nIDC);
}

// CString::Empty() (thiscall).
inline void StringEmpty(CString* value) {
  reinterpret_cast<void(__fastcall*)(CString*)>(::Empty)(value);
}

} // namespace

// FUNCTION: IMPERIALISM 0x00618df2
void __stdcall DDX_LBString(CDataExchange* pDX, undefined4 nIDC, CString* value) {
  HWND listbox = PrepareDdxControl(pDX, nIDC);
  if (pDX->m_bSaveAndValidate == 0) {
    SendMessageA(listbox, 0x18c, static_cast<WPARAM>(0xffffffff), value->data_ptr);
  } else {
    WPARAM selection = SendMessageA(listbox, 0x188, 0, 0);
    if (selection == static_cast<WPARAM>(0xffffffff)) {
      StringEmpty(value);
    } else {
      LRESULT rawItemData = SendMessageA(listbox, 0x18a, selection, 0);
      LPARAM normalized = value->EnsureCapacityAndSetLength(static_cast<int>(rawItemData));
      SendMessageA(listbox, 0x189, selection, normalized);
    }
    value->SetLengthAndTerminator(static_cast<int>(0xffffffff));
  }
}

// FUNCTION: IMPERIALISM 0x00618e72
void __stdcall DDX_LBStringExact(CDataExchange* pDX, undefined4 nIDC, CString* value) {
  HWND target = PrepareDdxControl(pDX, nIDC);
  if (pDX->m_bSaveAndValidate == 0) {
    WPARAM index = SendMessageA(target, 0x1a2, static_cast<WPARAM>(0xffffffff), value->data_ptr);
    if (index != static_cast<WPARAM>(0xffffffff)) {
      SendMessageA(target, 0x186, index, 0);
    }
  } else {
    DDX_LBString(pDX, nIDC, value);
  }
}
