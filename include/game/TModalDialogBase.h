#pragma once

#include "game/mfc.h" // CDialog (afxwin.h)

// Real MFC modal-template dialog base.
//
// The game's template dialogs are genuine CDialog subclasses: each constructor calls
// CDialog::CDialog(UINT nIDTemplate, CWnd* pParentWnd) at 0x006050d0 (a LIBRARY function
// linked from nafxcw.lib), installs a CDialog-copy vtable that overrides only the
// scalar-deleting-destructor slot, then brings the dialog up modelessly via
// CreateDialogIndirectA and drives it with an explicit modal loop.
//
// CDialog occupies 0x00-0x5b (sizeof(CDialog)==0x5c). This base adds the modal-create
// scratch state at 0x5c-0x73 (sizeof(TModalDialogBase)==0x74); subclasses append their
// embedded controls / strings from 0x74. The scratch fields map onto the writes made by
// PrepareAndCreateModalFromTemplate (0x49d360) / FinalizeModalDialogAndRestoreOwnerFocus
// (0x49d450) / CleanupModalCreateState (0x49d510):
//   0x5c modalCreated, 0x60 createdDialog (HWND), 0x64 finalizeState,
//   0x68 ownerWasDisabled, 0x6c ownerWindow (HWND), 0x70 loadedResource (HGLOBAL).
class TModalDialogBase : public CDialog {
public:
  // Forwards to CDialog::CDialog (0x006050d0) then zeroes the first three scratch fields,
  // exactly as every leaf constructor does right after the base call. Kept inline so
  // MSVC500 folds it into each leaf constructor, matching the original direct call to
  // 0x006050d0 followed by the [0x5c]/[0x60]/[0x64] stores.
  TModalDialogBase(UINT nIDTemplate, CWnd* pParentWnd)
      : CDialog(nIDTemplate, pParentWnd), modalCreated(0), createdDialog(nullptr),
        finalizeState(0) {}
  ~TModalDialogBase() override;

  int PrepareAndCreateModalFromTemplate();       // 0x0049d360
  int FinalizeModalDialogAndRestoreOwnerFocus(); // 0x0049d450

  int modalCreated;       // 0x5c
  HWND createdDialog;     // 0x60
  int finalizeState;      // 0x64
  int ownerWasDisabled;   // 0x68
  HWND ownerWindow;       // 0x6c
  HGLOBAL loadedResource; // 0x70
};
