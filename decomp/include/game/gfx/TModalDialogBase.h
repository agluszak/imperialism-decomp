#pragma once

#include "game/mfc.h" // CDialog (afxwin.h)

// VTABLE: IMPERIALISM 0x0063e5a0
class TModalDialogBase : public CDialog {
public:
  TModalDialogBase(UINT nIDTemplate, CWnd* pParentWnd); // 0x00480750
  ~TModalDialogBase() override;

  int DoModal() override;                          // 0x0049d450 (vtable index 48 / byte 0xc0)
  virtual int PrepareAndCreateModalFromTemplate(); // 0x0049d360 (vtable index 54 / byte 0xd8)
  virtual void CleanupModalCreateState();          // 0x0049d510 (vtable index 55 / byte 0xdc)

  int modalCreated;              // 0x5c
  int dialogCreatedSuccessfully; // 0x60
  int finalizeState;             // 0x64
  int ownerWasDisabled;          // 0x68
  HWND ownerWindow;              // 0x6c
  HGLOBAL loadedResource;        // 0x70
};
