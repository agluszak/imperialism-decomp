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
// PrepareAndCreateModalFromTemplate (0x49d360) / DoModal (0x49d450) / CleanupModalCreateState
// (0x49d510):
//   0x5c modalCreated, 0x60 createdDialog (HWND), 0x64 finalizeState,
//   0x68 ownerWasDisabled, 0x6c ownerWindow (HWND), 0x70 loadedResource (HGLOBAL).
//
// vtable 0x0063e5a0 = CDialog's vtable (0x0066fc2c) with: slot index 1 the class
// scalar-deleting destructor, slot index 48 (byte 0xc0) DoModal overridden with the game's
// modal loop, and two new tail virtuals at indices 54/55 (bytes 0xd8/0xdc)
// PrepareAndCreateModalFromTemplate / CleanupModalCreateState. A // VTABLE: marker is not
// claimed yet: reccmp can only pair the ~50 inherited CWnd/CDialog slots once the full MFC
// dialog vtable is annotated as LIBRARY (a separate prerequisite); the four dialog-specific
// slots here are already modelled as real virtuals.
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

  // Overrides CDialog::DoModal (vtable index 48) with the game's own modal loop that runs the
  // modeless dialog created by PrepareAndCreateModalFromTemplate and restores owner focus.
  int DoModal() override;                          // 0x0049d450 (vtable index 48 / byte 0xc0)
  virtual int PrepareAndCreateModalFromTemplate(); // 0x0049d360 (vtable index 54 / byte 0xd8)
  virtual void CleanupModalCreateState();          // 0x0049d510 (vtable index 55 / byte 0xdc)

  int modalCreated;       // 0x5c
  HWND createdDialog;     // 0x60
  int finalizeState;      // 0x64
  int ownerWasDisabled;   // 0x68
  HWND ownerWindow;       // 0x6c
  HGLOBAL loadedResource; // 0x70
};
