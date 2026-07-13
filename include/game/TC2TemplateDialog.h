#pragma once

#include <afxcmn.h> // CSliderCtrl

#include "game/TModalDialogBase.h" // CDialog-derived modal base
#include "game/mfc.h"              // CListBox (afxwin.h)

// Shared "C2" template modal dialog: a CDialog subclass (via TModalDialogBase, template
// id 0xc2) with an embedded CSliderCtrl at +0x74 and CListBox at +0xb0 (both CWnd-sized,
// 0x3c). Built by InitializeDialogTemplateC2WithTextState (0x0047cfd0) and driven modally
// through the TModalDialogBase template helpers. Used by the ID_800C
// city-view-selection and ID_8013 terrain-overlay command handlers.
class TC2TemplateDialog : public TModalDialogBase {
public:
  TC2TemplateDialog(void* initParam); // 0x0047cfd0
  // Destructor is compiler-generated (implicit) — destroys the embedded controls and the
  // CDialog base. Keeping it implicit avoids a second function body between the 0x0047cfd0
  // and 0x0047d1c0 constructor markers (reccmp requires one function per marker range).

  CSliderCtrl slider; // +0x74
  CListBox listbox;   // +0xb0
};

ASSERT_SIZE(TC2TemplateDialog, 0xec);

// Sibling "D2" template dialog (template id 0xd2, own vtable 0x646300): same
// TModalDialogBase base with a single embedded CListBox at +0x74. Built by
// InitializeDialogTemplateD2WithTextState (0x0047d1c0); used by the ID_8013
// terrain-overlay command handler.
class TD2TemplateDialog : public TModalDialogBase {
public:
  TD2TemplateDialog(void* initParam); // 0x0047d1c0
  // Destructor is compiler-generated (implicit); see TC2TemplateDialog above.

  CListBox listbox; // +0x74
};

ASSERT_SIZE(TD2TemplateDialog, 0xb0);
