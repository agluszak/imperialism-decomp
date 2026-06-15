#pragma once

#include "game/CWnd.h"
#include "game/CDC.h"

// MFC CClientDC — GetDC/ReleaseDC scoped device context.
// VTABLE: IMPERIALISM 0x0067249c
class CClientDC : public CDC {
public:
  explicit CClientDC(CWnd* pWnd);
  virtual ~CClientDC() override;
};
