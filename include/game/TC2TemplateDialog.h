#pragma once

#include <afxcmn.h> // CSliderCtrl

#include "game/TModalDialogBase.h" // CDialog-derived modal base
#include "game/mfc.h"              // CListBox (afxwin.h)

// Shared "C2" template modal dialog: a CDialog subclass (via TModalDialogBase, template
// id 0xc2) with an embedded CSliderCtrl at +0x74 and CListBox at +0xb0 (both CWnd-sized,
// 0x3c). Built by InitializeDialogTemplateC2WithTextState (0x0047cfd0) and driven modally
// through the TModalDialogBase template helpers. Used by the ID_800C
// city-view-selection and ID_8013 terrain-overlay command handlers.
// VTABLE: IMPERIALISM 0x006461f0
class TC2TemplateDialog : public TModalDialogBase {
public:
  TC2TemplateDialog(void* initParam); // 0x0047cfd0

  CSliderCtrl slider; // +0x74
  CListBox listbox;   // +0xb0

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047d160 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047d1a0 (vtable index 12)
};

ASSERT_SIZE(TC2TemplateDialog, 0xec);

// Sibling "D2" template dialog (template id 0xd2, own vtable 0x646300): same
// TModalDialogBase base with a single embedded CListBox at +0x74. Built by
// InitializeDialogTemplateD2WithTextState (0x0047d1c0); used by the ID_8013
// terrain-overlay command handler.
// VTABLE: IMPERIALISM 0x00646300
class TD2TemplateDialog : public TModalDialogBase {
public:
  TD2TemplateDialog(void* initParam); // 0x0047d1c0

  CListBox listbox; // +0x74

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047d310 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047d340 (vtable index 12)
};

ASSERT_SIZE(TD2TemplateDialog, 0xb0);

// Sibling "DB" template dialog (template id 0xdb, own vtable 0x646410): same TModalDialogBase
// base with a single embedded CListBox at +0x74. Built by
// InitializeDialogTemplateDBWithTextState (0x0047d360).
// VTABLE: IMPERIALISM 0x00646410
class TDBTemplateDialog : public TModalDialogBase {
public:
  TDBTemplateDialog(void* initParam); // 0x0047d360

  CListBox listbox; // +0x74

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047d420 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047d450 (vtable index 12)
};

ASSERT_SIZE(TDBTemplateDialog, 0xb0);

// Sibling "DC" template dialog (template id 0xdc, own vtable 0x646520): a TModalDialogBase
// with a single edit field exchanged as a 0..999 UINT (no embedded control object). Built by
// InitializeDialogTemplateDCBaseState (0x0047d470).
// VTABLE: IMPERIALISM 0x00646520
class TDCTemplateDialog : public TModalDialogBase {
public:
  TDCTemplateDialog(void* initParam); // 0x0047d470

  unsigned int value74; // +0x74 — DDX_Text edit value (validated 0..999)

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047d4e0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047d520 (vtable index 12)
};

ASSERT_SIZE(TDCTemplateDialog, 0x78);

// Sibling "DE" template dialog (template id 0xde, own vtable 0x646630): a TModalDialogBase
// with an embedded CListBox at +0x74 plus two DDX_Text UINT fields at +0xb0/+0xb4. Built by
// InitializeDialogTemplateDEWithTextState (0x0047dba0).
// VTABLE: IMPERIALISM 0x00646630
class TDETemplateDialog : public TModalDialogBase {
public:
  TDETemplateDialog(void* initParam); // 0x0047dba0

  CListBox listbox;     // +0x74
  unsigned int valueB0; // +0xb0 — DDX_Text control 0x422
  unsigned int valueB4; // +0xb4 — DDX_Text control 0x421

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047dc70 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047dcc0 (vtable index 12)
};

ASSERT_SIZE(TDETemplateDialog, 0xb8);
