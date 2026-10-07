#pragma once

#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064afd8
class CMcEditWindow : public CEdit {
public:
  CMcEditWindow() : CEdit() {} // inlined into TEditText::Open in the original
  // FUNCTION: IMPERIALISM 0x00490a30
  ~CMcEditWindow() override {}

protected:
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);

  DECLARE_MESSAGE_MAP()
};
