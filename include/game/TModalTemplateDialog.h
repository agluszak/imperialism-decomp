#pragma once

#include "game/TModalDialogBase.h"
#include "game/mfc.h"

// Template-driven modal dialog controller: a CDialog subclass (via TModalDialogBase) that
// owns the modal-create teardown. All modal-create scratch state lives in the
// TModalDialogBase base (0x5c-0x73); this level adds only behaviour, no fields.
class TModalTemplateDialog : public TModalDialogBase {
public:
  TModalTemplateDialog(UINT templateId, CWnd* pParentWnd)
      : TModalDialogBase(templateId, pParentWnd) {}
  ~TModalTemplateDialog() override;

  void CleanupModalCreateState();         // 0x0049d510
  void DestroyListBoxAndHotKeyChildren(); // 0x004152e0
  BOOL UpdateData(BOOL saveAndValidate);

  int DialogResult() const {
    return reinterpret_cast<const int*>(this)[0x2c / 4];
  }
};

// Low-disk-space warning dialog (template id 0x98, own vtable 0x66f5d8): a
// TModalTemplateDialog with a prompt string at +0x74.
class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  explicit TLowDiskWarningDialog(void* initParam = nullptr); // 0x005e1bc0
  void SetPromptText(LPCSTR text);

  CString promptText; // 0x74
};
