#pragma once

#include "game/gfx/TModalDialogBase.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00646958
class TAutoResolutionDialog : public TModalDialogBase {
public:
  explicit TAutoResolutionDialog(void* initParam = NULL);
  ~TAutoResolutionDialog() override;

  int DialogResult() const {
    return m_nModalResult;
  }

  CButton primaryDialogControl;
  CListBox secondaryDialogControl;
  int autoResolutionCheckState;

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047e100 (index 12)
};
