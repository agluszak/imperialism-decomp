#pragma once

#include "game/gfx/TModalDialogBase.h"
#include "game/mfc.h"

// Template-driven modal dialog controller. TModalDialogBase owns the modal-create
// scratch state and teardown; this level adds behavior but no fields.
class TModalTemplateDialog : public TModalDialogBase {
public:
  TModalTemplateDialog(UINT templateId, CWnd* pParentWnd)
      : TModalDialogBase(templateId, pParentWnd) {}

  int DialogResult() const {
    return m_nModalResult;
  }
};

// Low-disk-space warning dialog (template id 0x98, own vtable 0x66f5d8): a
// TModalTemplateDialog with a prompt string at +0x74.
// VTABLE: IMPERIALISM 0x0066f5d8
class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  // FUNCTION: IMPERIALISM 0x00415b70
  ~TLowDiskWarningDialog() override {}
  explicit TLowDiskWarningDialog(void* initParam = nullptr); // 0x005e1bc0

  CString promptText; // 0x74

protected:
  BOOL OnInitDialog() override;                     // 0x005e1ce0 (vtable index 49)
  void DoDataExchange(CDataExchange* pDX) override; // 0x005e1c90 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x005e1cc0 (index 12)
};
