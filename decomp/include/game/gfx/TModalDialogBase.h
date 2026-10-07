#pragma once

#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063e5a0
class TModalDialogBase : public CDialog {
public:
  TModalDialogBase(UINT nIDTemplate, CWnd* pParentWnd);
  ~TModalDialogBase() override;

  int DoModal() override;
  virtual int PrepareAndCreateModalFromTemplate();
  virtual void CleanupModalCreateState();

  int modalCreated;
  int dialogCreatedSuccessfully;
  int finalizeState;
  int ownerWasDisabled;
  HWND ownerWindow;
  HGLOBAL loadedResource;
};
