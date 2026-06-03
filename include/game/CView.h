#pragma once

#include "decomp_types.h"

// MFC CView: a window attached to a CDocument. Each view stores its owning
// document at +0x3c. Only the fields we have grounded are modeled here; the
// real CView is larger, so we do not assert a total size.
struct CView {
  char pad_00[0x3c];
  void* m_pDocument;
};
