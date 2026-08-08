#pragma once

#include "game/mfc.h"

// Host CEdit subclass for TEditText's live "EDIT" control. TEditText::Open
// (0x004907a0) constructs one inline (CWnd base ctor, then the vtable store
// 0x0064afd8) and creates it as an "EDIT" child of the control's native window.
// Its entire override surface is one WM_CHAR message-map handler (map
// 0x00649538, single ON_WM_CHAR entry) that forwards Return/Linefeed/Escape to
// the main view host before default edit processing. GetRuntimeClass stays the
// base's — the original vtable slot 0 (0x00623996) returns the CEdit runtime
// class, which pins the base as CEdit. This local name describes its message-map role;
// the class has no independent RTTI name in the Windows image.
// VTABLE: IMPERIALISM 0x0064afd8
class CMcEditWindow : public CEdit {
public:
  CMcEditWindow() : CEdit() {} // inlined into TEditText::Open in the original
  // The ordinary destructor's canonical address is an incremental-link fold
  // island (jmp chain onto CProgressCtrl::~CProgressCtrl in the MFC region);
  // the folded_symbol_group row in config/template_aliases.csv proves it.
  // FUNCTION: IMPERIALISM 0x00490a30
  ~CMcEditWindow() override {}

protected:
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x00489e70

  DECLARE_MESSAGE_MAP()
};
