#pragma once

#include <afxcmn.h> // CSliderCtrl

#include "game/gfx/TModalDialogBase.h" // CDialog-derived modal base
#include "game/mfc.h"              // CListBox (afxwin.h)

class CDib;
struct GameSetup;

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
// base with a single embedded CSliderCtrl at +0x74 (ctor installs the CSliderCtrl vtable
// 0x6714cc). Built by InitializeDialogTemplateDBWithTextState (0x0047d360).
// VTABLE: IMPERIALISM 0x00646410
class TDBTemplateDialog : public TModalDialogBase {
public:
  TDBTemplateDialog(void* initParam); // 0x0047d360

  CSliderCtrl slider; // +0x74

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
// with an embedded CSliderCtrl at +0x74 (ctor installs CSliderCtrl vtable 0x6714cc) plus two
// DDX_Text UINT fields at +0xb0/+0xb4. Built by InitializeDialogTemplateDEWithTextState
// (0x0047dba0).
// VTABLE: IMPERIALISM 0x00646630
class TDETemplateDialog : public TModalDialogBase {
public:
  TDETemplateDialog(void* initParam); // 0x0047dba0

  CSliderCtrl slider;                  // +0x74
  unsigned int populationAdjustmentB0; // +0xb0 — DDX_Text control 0x422
  unsigned int commodityAdjustmentB4;  // +0xb4 — DDX_Text control 0x421

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047dc70 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047dcc0 (vtable index 12)
};

ASSERT_SIZE(TDETemplateDialog, 0xb8);

// Sibling "DF" template dialog (template id 0xdf, own vtable 0x646740). Unlike its
// TModalDialogBase siblings this is a PLAIN CDialog subclass: vtable slot 0xc0 is the library
// CDialog::DoModal (0x6051b9) and the TModalDialogBase modal-loop slots at 0xd8/0xdc are
// absent, and its ctor writes only its own vtable (no TModalDialogBase intermediate). Its data
// — one edit value + five checkbox flags — occupies 0x5c-0x70, right after the CDialog base
// (0x5c). Built by InitializeDialogTemplateDFBaseState (0x0047dce0).
// VTABLE: IMPERIALISM 0x00646740
class TDFTemplateDialog : public CDialog {
public:
  TDFTemplateDialog(void* initParam); // 0x0047dce0

  int editValue5c; // 0x5c — DDX_Text control 0x421
  int checkFlag60; // 0x60 — DDX_Check control 0x3f5
  int checkFlag64; // 0x64 — DDX_Check control 0x422
  int checkFlag68; // 0x68 — DDX_Check control 0x423
  int checkFlag6c; // 0x6c — DDX_Check control 0x424
  int checkFlag70; // 0x70 — DDX_Check control 0x427

protected:
  BOOL OnInitDialog() override;                     // 0x0047de10 (slot 0xc4)
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047dd60 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047ddf0 (vtable index 12)
};

ASSERT_SIZE(TDFTemplateDialog, 0x74);

// Sibling "FA" template dialog (template id 0xfa, own vtable 0x646848): TModalDialogBase with an
// embedded CListBox at +0x74 (vtable 0x671d1c). Its DoDataExchange override is an empty stub —
// the listbox is wired up outside DDX. Built by InitializeDialogTemplateFAWithTextState
// (0x0047de40).
// VTABLE: IMPERIALISM 0x00646848
class TFATemplateDialog : public TModalDialogBase {
public:
  TFATemplateDialog(void* initParam); // 0x0047de40

  CListBox listbox; // +0x74

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047df90 (empty body)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047dfb0 (vtable index 12)
};

ASSERT_SIZE(TFATemplateDialog, 0xb0);

// Sibling "AD" template dialog (template id 0xad, own vtable 0x646d68): TModalDialogBase with an
// embedded CListBox at +0x74, an OnInitDialog override, and a DDX_Control-bound listbox. Built
// by InitializeDialogTemplateADWithTextState (0x0047f450).
// VTABLE: IMPERIALISM 0x00646d68
class TADTemplateDialog : public TModalDialogBase {
public:
  TADTemplateDialog(void* initParam); // 0x0047f450

  CListBox listbox; // +0x74

protected:
  BOOL OnInitDialog() override;                     // 0x0047f620 (slot 0xc4)
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047f5d0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047f600 (vtable index 12)
};

ASSERT_SIZE(TADTemplateDialog, 0xb0);

// Sibling "104" template dialog (template id 0x104, own vtable 0x646ea0): TModalDialogBase with
// an embedded CListBox at +0x74 (DDX_Control 0x435). Built by
// InitializeDialogTemplate104WithRegionState (0x00480a10).
// VTABLE: IMPERIALISM 0x00646ea0
class T104TemplateDialog : public TModalDialogBase {
public:
  T104TemplateDialog(void* initParam); // 0x00480a10

  CListBox listbox; // +0x74

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x00480ad0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x00480b00 (vtable index 12)
};

ASSERT_SIZE(T104TemplateDialog, 0xb0);

// Sibling "A7" template dialog (template id 0xa7, own vtable 0x647740): a PLAIN CDialog subclass
// (base 0x5c) with one CString edit field at +0x5c (DDX_Text 0x3fc). Built by
// InitializeDialogTemplateA7WithSharedText (0x00481770).
// VTABLE: IMPERIALISM 0x00647740
class TA7TemplateDialog : public CDialog {
public:
  TA7TemplateDialog(void* initParam); // 0x00481770

  CString text5c; // +0x5c — DDX_Text control 0x3fc

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x004818a0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x004818d0 (vtable index 12)
};

ASSERT_SIZE(TA7TemplateDialog, 0x60);

// Sibling "AB" template dialog (template id 0xab, own vtable 0x647b60): a PLAIN CDialog subclass
// (base 0x5c) with two CString edit fields at +0x5c/+0x60 (DDX_Text 0x3fd/0x3fe). Built by
// InitializeDialogTemplateABWithDualTextState (0x00481b30).
// VTABLE: IMPERIALISM 0x00647b60
class TABTemplateDialog : public CDialog {
public:
  TABTemplateDialog(void* initParam); // 0x00481b30

  CString text5c; // +0x5c — DDX_Text control 0x3fd
  CString text60; // +0x60 — DDX_Text control 0x3fe

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x00481ca0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x00481ce0 (vtable index 12)
};

ASSERT_SIZE(TABTemplateDialog, 0x64);

// Sibling "AE" template dialog (template id 0xae, own vtable 0x647d70): a PLAIN CDialog subclass
// (base 0x5c) with two CString edit fields at +0x5c/+0x60 (DDX_Text 0x400/0x401). Built by
// InitializeDialogTemplateAEWithDualTextState (0x00481dc0).
// VTABLE: IMPERIALISM 0x00647d70
class TAETemplateDialog : public CDialog {
public:
  TAETemplateDialog(void* initParam); // 0x00481dc0

  CString text5c; // +0x5c — DDX_Text control 0x400
  CString text60; // +0x60 — DDX_Text control 0x401

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x00481f30 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x00481f70 (vtable index 12)
};

ASSERT_SIZE(TAETemplateDialog, 0x64);

// Sibling "B1" template dialog (template id 0xb1, own vtable 0x647f80): a PLAIN CDialog subclass
// (base 0x5c) with one CString edit field at +0x5c (DDX_Text 0x403). Built by
// InitializeDialogTemplateB1WithSharedText (0x00482050).
// VTABLE: IMPERIALISM 0x00647f80
class TB1TemplateDialog : public CDialog {
public:
  TB1TemplateDialog(void* initParam); // 0x00482050

  CString text5c; // +0x5c — DDX_Text control 0x403

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x00482180 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x004821b0 (vtable index 12)
};

ASSERT_SIZE(TB1TemplateDialog, 0x60);

// Sibling "DD" picture-preview template dialog (template id 0xdd, own vtable 0x63e6b0):
// TModalDialogBase-derived, previews a CDib picture (sized to the window in OnInitDialog, drawn
// in OnPaint) and optionally overlays a red silhouette outline/fill built from the picture's
// non-transparent pixels (heap buffer at +0x8c, freed in the destructor). Built by
// InitializeDialogTemplateDDPictureState (0x0047d540).
// VTABLE: IMPERIALISM 0x0063e6b0
class TDDTemplateDialog : public TModalDialogBase {
public:
  TDDTemplateDialog(void* initParam); // 0x0047d540
  ~TDDTemplateDialog() override;      // 0x00413c30 — frees the outline buffer

  CDib* picture;        // 0x74 source picture/DIB (not owned here; set by the caller)
  int drawOutline;      // 0x78 != 0 -> draw red silhouette polyline in OnPaint
  int fillPolygon;      // 0x7c != 0 -> fill silhouette region red in OnPaint
  int renderMode;       // 0x80 OnPaint blit-mode selector (0 = simple/blit, != 0 = masked stretch)
  unsigned int flag84;  // 0x84 = flags88 & 1 (computed in OnInitDialog)
  unsigned int flags88; // 0x88 flags source (set by the caller)
  int* outlinePolygon;  // 0x8c heap silhouette buffer: [0]=count, POINT pairs from index 2
  const char* windowTitle; // 0x90 LPCSTR passed to SetWindowText (set by the caller)

protected:
  BOOL OnInitDialog() override;                            // 0x0047dae0 (slot 0xc4)
  void DoDataExchange(CDataExchange* pDX) override;        // 0x0047d5b0 (empty body)
  afx_msg void OnPaint();                                  // 0x0047d5f0
  afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point); // 0x0047db80
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d5d0 (vtable index 12)
};

ASSERT_SIZE(TDDTemplateDialog, 0x94);

// Sibling "64" template dialog (template id 0x64, own vtable 0x63e498): a PLAIN CDialog subclass
// with no data members and a trivial OnInitDialog override. Constructed inline by its only
// driver ShowDialogTemplate64Modal (0x00413700), so it has no standalone constructor function.
// VTABLE: IMPERIALISM 0x0063e498
class T64TemplateDialog : public CDialog {
public:
  T64TemplateDialog() : CDialog(0x64) {}

  unsigned char scratch5c[0x74 - 0x5c]; // 0x5c-0x74 — template scratch written by the ctor

protected:
  BOOL OnInitDialog() override;                     // 0x00415380 (slot 0xc4)
  void DoDataExchange(CDataExchange* pDX) override; // 0x004136c0 (empty body)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x004136e0 (vtable index 12)
};

ASSERT_SIZE(T64TemplateDialog, 0x74);

// Sibling "D0" template dialog (template id 0xd0, own vtable 0x64bac0): a PLAIN CDialog subclass
// with an embedded CListBox at +0x5c (DDX_Control 0x419). OnOK is a no-op (suppresses default
// close) and OnCancel minimizes instead of closing. Built by
// InitializeDialogTemplateD0WithTextState (0x0049bcd0).
// VTABLE: IMPERIALISM 0x0064bac0
class TD0TemplateDialog : public CDialog {
public:
  TD0TemplateDialog(void* initParam); // 0x0049bcd0

  CListBox listbox; // +0x5c

protected:
  void OnOK() override;                             // 0x0049bfb0 (empty)
  void OnCancel() override;                         // 0x0049bfd0 (SW_MINIMIZE)
  void DoDataExchange(CDataExchange* pDX) override; // 0x0049bf60 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0049bf90 (vtable index 12)
};

ASSERT_SIZE(TD0TemplateDialog, 0x98);

// Sibling "E0" full-screen overlay template dialog (template id 0xe0, own vtable 0x64b960): a
// PLAIN CDialog subclass with no DDX members. Overrides PreCreateWindow (forces a huge window)
// and OnInitDialog (custom cursor + 2000x2000 MoveWindow); its message map carries the input
// handlers (WM_CHAR/KEYDOWN/mouse/cursor/paint — follow-up). Built by InitializeDialogTemplateE0
// (0x005dee50).
// VTABLE: IMPERIALISM 0x0064b960
class TE0TemplateDialog : public CDialog {
public:
  TE0TemplateDialog(void* initParam); // 0x005dee50
  ~TE0TemplateDialog() override;      // 0x00498d60 — ReleaseCapture()

  unsigned char scratch5c[0x74 - 0x5c]; // 0x5c-0x74 — template scratch written by the ctor

protected:
  BOOL PreCreateWindow(CREATESTRUCT& cs) override;  // 0x005def40 (slot 0x64)
  BOOL OnInitDialog() override;                     // 0x005def70 (slot 0xc4)
  void DoDataExchange(CDataExchange* pDX) override; // 0x005dee80 (empty body)

  // Full-screen overlay input handlers: any key or L/R click dismisses; WM_SETCURSOR reasserts
  // the custom cursor; NCPAINT/PAINT suppress painting.
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);        // 0x005deec0
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);     // 0x005deee0
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point);             // 0x005def00
  afx_msg void OnRButtonDown(UINT nFlags, CPoint point);             // 0x005def20
  afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message); // 0x005defe0
  afx_msg void OnNcPaint();                                          // 0x005df020
  afx_msg void OnPaint();                                            // 0x005df040

  DECLARE_MESSAGE_MAP() // GetMessageMap 0x005deea0 (vtable index 12)
};

ASSERT_SIZE(TE0TemplateDialog, 0x74);

void ShowBlockingWaitOverlayDialog(void); // 0x00498cc0

// Windows game-setup dialog (template id 0xa1, own vtable 0x647428): three policy sliders,
// two DDX checkboxes, and the caller-owned GameSetup record at +0x118.
// VTABLE: IMPERIALISM 0x00647428
class TA1TemplateDialog : public CDialog {
public:
  TA1TemplateDialog(void* initParam);        // 0x004813a0
  void SetGameSetupValues(GameSetup* setup); // 0x004821d0

  CSliderCtrl slider5c; // +0x5c
  CSliderCtrl slider98; // +0x98
  CSliderCtrl sliderD4; // +0xd4
  int check110;         // +0x110 — DDX_Check control 0x404
  int check114;         // +0x114 — DDX_Check control 0x405
  GameSetup* state118;  // +0x118

protected:
  BOOL OnInitDialog() override;                     // 0x004821f0 (slot 0xc4)
  void OnOK() override;                             // 0x00482300 (slot 0xcc)
  void DoDataExchange(CDataExchange* pDX) override; // 0x00481540 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x004815d0 (vtable index 12)
};

ASSERT_SIZE(TA1TemplateDialog, 0x11c);
