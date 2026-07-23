#pragma once

#include "game/gfx/TModalDialogBase.h"
#include "game/mfc.h"

// Template-driven modal dialog controller: a CDialog subclass (via TModalDialogBase) that
// owns the modal-create teardown. All modal-create scratch state lives in the
// TModalDialogBase base (0x5c-0x73); this level adds only behaviour, no fields.
class TModalTemplateDialog : public TModalDialogBase {
public:
  TModalTemplateDialog(UINT templateId, CWnd* pParentWnd)
      : TModalDialogBase(templateId, pParentWnd) {}
  ~TModalTemplateDialog() override;

  void DestroyListBoxAndHotKeyChildren(); // 0x004152e0

  int DialogResult() const {
    return m_nModalResult;
  }
};

// Low-disk-space warning dialog (template id 0x98, own vtable 0x66f5d8): a
// TModalTemplateDialog with a prompt string at +0x74.
// VTABLE: IMPERIALISM 0x0066f5d8
class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  explicit TLowDiskWarningDialog(void* initParam = nullptr); // 0x005e1bc0
  void SetPromptText(LPCSTR text);

  CString promptText; // 0x74

protected:
  BOOL OnInitDialog() override;                     // 0x005e1ce0 (vtable index 49)
  void DoDataExchange(CDataExchange* pDX) override; // 0x005e1c90 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x005e1cc0 (index 12)
};
