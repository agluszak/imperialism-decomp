#pragma once

#include "game/gfx/TModalDialogBase.h"
#include "game/mfc.h"

class TModalTemplateDialog : public TModalDialogBase {
public:
  TModalTemplateDialog(UINT templateId, CWnd* pParentWnd)
      : TModalDialogBase(templateId, pParentWnd) {}

  int DialogResult() const {
    return m_nModalResult;
  }
};

// VTABLE: IMPERIALISM 0x0066f5d8
class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  // FUNCTION: IMPERIALISM 0x00415b70
  ~TLowDiskWarningDialog() override {}
  explicit TLowDiskWarningDialog(void* initParam = NULL);

  CString promptText;

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x005e1cc0 (index 12)
};
