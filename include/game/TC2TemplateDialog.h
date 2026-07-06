#pragma once

#include <afxcmn.h> // CSliderCtrl

#include "game/TControl.h" // TModalTemplateDialogBase
#include "game/mfc.h"      // CListBox (afxwin.h)

// Shared "C2" template modal dialog: a TModalTemplateDialogBase (template id 0xc2) with
// an embedded CSliderCtrl at +0x74 and CListBox at +0xb0 (both CWnd-sized, 0x3c). Built
// by InitializeDialogTemplateC2WithTextState (0x0047cfd0) and driven modally through the
// TModalTemplateDialogBase template helpers. Used by the ID_800C city-view-selection and
// ID_8013 terrain-overlay command handlers (bd imperialism-decomp-ve8.5 / ve8.2).
// Provisional layout model: the runtime object's own vtable is 0x006461f0 (a
// CDialog/CCmdTarget-family vtable, not yet fully recovered), but the handlers only
// touch the embedded CSliderCtrl (+0x74) / CListBox (+0xb0) and the
// TModalTemplateDialogBase template lifecycle directly, so no // VTABLE is claimed here.
class TC2TemplateDialog : public TModalTemplateDialogBase {
public:
  TC2TemplateDialog(void* initParam); // 0x0047cfd0
  ~TC2TemplateDialog() override;

  CSliderCtrl slider; // +0x74
  CListBox listbox;   // +0xb0
};

ASSERT_SIZE(TC2TemplateDialog, 0xec);

// Sibling "D2" template dialog (template id 0xd2, own vtable 0x646300): same
// TModalTemplateDialogBase base with a single embedded CListBox at +0x74. Built by
// InitializeDialogTemplateD2WithTextState (0x0047d1c0); used by the ID_8013
// terrain-overlay command handler (bd imperialism-decomp-ve8.2). Same provisional-model
// caveat as TC2TemplateDialog (its own vtable is not claimed here).
class TD2TemplateDialog : public TModalTemplateDialogBase {
public:
  TD2TemplateDialog(void* initParam); // 0x0047d1c0
  ~TD2TemplateDialog() override;

  CListBox listbox; // +0x74
};

ASSERT_SIZE(TD2TemplateDialog, 0xb0);
