#pragma once

#include "game/mfc.h"

// Host CEdit subclass for TEditText's live "EDIT" control. TEditText::Open
// (0x004907a0) constructs one inline (CWnd base ctor, then the vtable store
// 0x0064afd8) and creates it as an "EDIT" child of the control's native window.
// Its entire override surface is one WM_CHAR message-map handler (map
// 0x00649538, single ON_WM_CHAR entry) that forwards Return/Linefeed/Escape to
// the main view host before default edit processing. GetRuntimeClass stays the
// base's — the original vtable slot 0 (0x00623996) returns the CEdit runtime
// class, which pins the base as CEdit; the class itself has no own RTTI, so
// the name here is provisional.
// VTABLE: IMPERIALISM 0x0064afd8
class CMcEditWindow : public CEdit {
public:
  CMcEditWindow() : CEdit() {} // inlined into TEditText::Open in the original

protected:
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x00489e70

  DECLARE_MESSAGE_MAP()
};
