#include "game/CClientDC.h"
#include "decomp_types.h"

typedef void* hwnd_t;
typedef void* hdc_t;

extern "C" hdc_t __stdcall GetDC(hwnd_t hwnd);
extern "C" int __stdcall ReleaseDC(hwnd_t hwnd, hdc_t hdc);
undefined4 AfxThrowResourceException(void);

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00613791
CClientDC::CClientDC(void* windowParent)
    : CDC() {
  hwnd_t hwnd = 0;
  if (windowParent != 0) {
    hwnd = *reinterpret_cast<hwnd_t*>(static_cast<char*>(windowParent) + 0x1c);
  }
  m_hWnd = reinterpret_cast<int>(hwnd);
  hdc_t hdc = GetDC(hwnd);
  if (!AttachOutput(reinterpret_cast<int>(hdc))) {
    reinterpret_cast<void(__cdecl*)()>(AfxThrowResourceException)();
  }
}

// LIBRARY: IMPERIALISM 0x00613803
// CClientDC::~CClientDC
