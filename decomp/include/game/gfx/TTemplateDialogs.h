#pragma once

#include <afxcmn.h> // CSliderCtrl

#include "game/gfx/TModalDialogBase.h" // CDialog-derived modal base
#include "game/mfc.h"                  // CListBox (afxwin.h)

class CDib;
struct GameSetup;

// VTABLE: IMPERIALISM 0x006461f0
class TWarpToScreenDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x0047d0c0
  ~TWarpToScreenDialog() override {}
  TWarpToScreenDialog(void* initParam);

  CSliderCtrl slider;
  CListBox listbox;

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d1a0 (vtable index 12)
};

ASSERT_SIZE(TWarpToScreenDialog, 0xec);

// VTABLE: IMPERIALISM 0x00646300
class TConductDiplomacyDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x0047d280
  ~TConductDiplomacyDialog() override {}
  TConductDiplomacyDialog(void* initParam);

  CListBox listbox;

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d340 (vtable index 12)
};

ASSERT_SIZE(TConductDiplomacyDialog, 0xb0);

// VTABLE: IMPERIALISM 0x00646410
class TSwitchGreatPowerDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x00413ed0
  ~TSwitchGreatPowerDialog() override {}
  TSwitchGreatPowerDialog(void* initParam);

  CSliderCtrl slider;

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d450 (vtable index 12)
};

ASSERT_SIZE(TSwitchGreatPowerDialog, 0xb0);

// VTABLE: IMPERIALISM 0x00646520
class TRunOffTurnsDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x00414070
  ~TRunOffTurnsDialog() override {}
  TRunOffTurnsDialog(void* initParam);

  unsigned int turnCount; // DDX_Text edit value (validated 0..999)

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d520 (vtable index 12)
};

ASSERT_SIZE(TRunOffTurnsDialog, 0x78);

// VTABLE: IMPERIALISM 0x00646630
class TBequeathGoodiesDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x00414320
  ~TBequeathGoodiesDialog() override {}
  TBequeathGoodiesDialog(void* initParam);

  CSliderCtrl slider;
  unsigned int populationAdjustment; // DDX_Text control 0x422
  unsigned int commodityAdjustment;  // DDX_Text control 0x421

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047dcc0 (vtable index 12)
};

ASSERT_SIZE(TBequeathGoodiesDialog, 0xb8);

// VTABLE: IMPERIALISM 0x00646740
class TPeekAtDibDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x004145d0
  ~TPeekAtDibDialog() override {}
  TPeekAtDibDialog(void* initParam);

  int editValue;        // DDX_Text control 0x421
  int buildOutlineMask; // DDX_Check control 0x3f5
  int drawOutline;      // DDX_Check control 0x422
  int fillPolygon;      // DDX_Check control 0x423
  int renderMode;       // DDX_Check control 0x424
  int unreadCheck;      // DDX_Check control 0x427

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047ddf0 (vtable index 12)
};

ASSERT_SIZE(TPeekAtDibDialog, 0x74);

// VTABLE: IMPERIALISM 0x00646848
class TFATemplateDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x0047df00
  ~TFATemplateDialog() override {}
  TFATemplateDialog(void* initParam);

  CListBox listbox;

protected:
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047df90 (empty body)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047dfb0 (vtable index 12)
};

ASSERT_SIZE(TFATemplateDialog, 0xb0);

// VTABLE: IMPERIALISM 0x00646d68
class TADTemplateDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x0047f510
  ~TADTemplateDialog() override {}
  TADTemplateDialog(void* initParam);

  int AddListboxText(const CString* text);

  CListBox listbox;

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047f600 (vtable index 12)
};

ASSERT_SIZE(TADTemplateDialog, 0xb0);

// VTABLE: IMPERIALISM 0x00646ea0
class TPickGameDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x00480790
  ~TPickGameDialog() override {}
  TPickGameDialog(void* initParam);

  CListBox listbox;

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x00480b00 (vtable index 12)
};

ASSERT_SIZE(TPickGameDialog, 0xb0);

// VTABLE: IMPERIALISM 0x00647050
class T102TemplateDialog : public TModalDialogBase {
public:
  // FUNCTION: IMPERIALISM 0x00481160
  ~T102TemplateDialog() override {}
  T102TemplateDialog(void* initParam);

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x00481200 (vtable index 12)
};

ASSERT_SIZE(T102TemplateDialog, 0x74);

// VTABLE: IMPERIALISM 0x00646b58
class TA3TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x0047f300
  ~TA3TemplateDialog() override {}
  TA3TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  virtual void VerifyDialogContext(int unusedA, int unusedB);
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA3TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00646c60
class TA4TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x0047f3c0
  ~TA4TemplateDialog() override {}
  TA4TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  virtual void VerifyDialogContext(int unusedA, int unusedB);
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA4TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647530
class TA5TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481650
  ~TA5TemplateDialog() override {}
  TA5TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA5TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647638
class TA6TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481710
  ~TA6TemplateDialog() override {}
  TA6TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA6TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647848
class TA8TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481950
  ~TA8TemplateDialog() override {}
  TA8TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA8TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647950
class TA9TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481a10
  ~TA9TemplateDialog() override {}
  TA9TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TA9TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647a58
class TAATemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481ad0
  ~TAATemplateDialog() override {}
  TAATemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TAATemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647c68
class TACTemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481d60
  ~TACTemplateDialog() override {}
  TACTemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TACTemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647e78
class TAFTemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481ff0
  ~TAFTemplateDialog() override {}
  TAFTemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TAFTemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00648088
class TF7TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00482400
  ~TF7TemplateDialog() override {}
  TF7TemplateDialog(void* initParam);

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  afx_msg void OnCommand428();
  afx_msg void OnCommand3();
  afx_msg void OnCommand4();
  DECLARE_MESSAGE_MAP()
};

ASSERT_SIZE(TF7TemplateDialog, 0x5c);

// VTABLE: IMPERIALISM 0x00647740
class TA7TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481830
  ~TA7TemplateDialog() override {}
  TA7TemplateDialog(void* initParam);

  CString text5c; // DDX_Text control 0x3fc

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x004818d0 (vtable index 12)
};

ASSERT_SIZE(TA7TemplateDialog, 0x60);

// VTABLE: IMPERIALISM 0x00647b60
class TABTemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481c20
  ~TABTemplateDialog() override {}
  TABTemplateDialog(void* initParam);

  CString text5c; // DDX_Text control 0x3fd
  CString text60; // DDX_Text control 0x3fe

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x00481ce0 (vtable index 12)
};

ASSERT_SIZE(TABTemplateDialog, 0x64);

// VTABLE: IMPERIALISM 0x00647d70
class TAETemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00481eb0
  ~TAETemplateDialog() override {}
  TAETemplateDialog(void* initParam);

  CString text5c; // DDX_Text control 0x400
  CString text60; // DDX_Text control 0x401

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x00481f70 (vtable index 12)
};

ASSERT_SIZE(TAETemplateDialog, 0x64);

// VTABLE: IMPERIALISM 0x00647f80
class TB1TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x00482110
  ~TB1TemplateDialog() override {}
  TB1TemplateDialog(void* initParam);

  CString text5c; // DDX_Text control 0x403

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x004821b0 (vtable index 12)
};

ASSERT_SIZE(TB1TemplateDialog, 0x60);

// VTABLE: IMPERIALISM 0x0063e6b0
class TDibPreviewDialog : public TModalDialogBase {
public:
  TDibPreviewDialog(void* initParam);
  ~TDibPreviewDialog() override; // frees the outline buffer

  CDib* picture;         // 0x74 source picture/DIB (not owned here; set by the caller)
  int drawOutline;       // 0x78 != 0 -> draw red silhouette polyline in OnPaint
  int fillPolygon;       // 0x7c != 0 -> fill silhouette region red in OnPaint
  int renderMode;        // 0x80 OnPaint blit-mode selector (0 = simple/blit, != 0 = masked stretch)
  unsigned int flag84;   // 0x84 = flags88 & 1 (computed in OnInitDialog)
  unsigned int flags88;  // 0x88 flags source (set by the caller)
  POINT* outlinePolygon; // 0x8c heap silhouette buffer: [0].x=count, vertices from [1]
  const char* windowTitle; // 0x90 LPCSTR passed to SetWindowText (set by the caller)

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047d5b0 (empty body)
  afx_msg void OnPaint();
  afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0047d5d0 (vtable index 12)
};

ASSERT_SIZE(TDibPreviewDialog, 0x94);

// VTABLE: IMPERIALISM 0x0063e498
class T64TemplateDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x004136a0
  ~T64TemplateDialog() override {}
  T64TemplateDialog() : CDialog(0x64) {}

  unsigned char scratch5c[0x74 - 0x5c]; // template scratch written by the ctor

protected:
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override; // 0x004136c0 (empty body)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x004136e0 (vtable index 12)
};

ASSERT_SIZE(T64TemplateDialog, 0x74);

// VTABLE: IMPERIALISM 0x0064bac0
class TTraceDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x0049baf0
  ~TTraceDialog() override {}
  TTraceDialog(void* initParam);

  CListBox listbox;

  int dialogCreated;

  void AppendTraceTextAndFlushCompleteLines(const char* text);

protected:
  void OnOK() override;     // 0x0049bfb0 (empty)
  void OnCancel() override; // 0x0049bfd0 (SW_MINIMIZE)
  void DoDataExchange(CDataExchange* pDX) override;
  DECLARE_MESSAGE_MAP() // GetMessageMap 0x0049bf90 (vtable index 12)
};

ASSERT_SIZE(TTraceDialog, 0x9c);

// VTABLE: IMPERIALISM 0x0064b960
class TE0TemplateDialog : public CDialog {
public:
  TE0TemplateDialog(void* initParam);
  ~TE0TemplateDialog() override; // ReleaseCapture()

  unsigned char scratch5c[0x74 - 0x5c]; // template scratch written by the ctor

protected:
  BOOL PreCreateWindow(CREATESTRUCT& cs) override;
  BOOL OnInitDialog() override;
  void DoDataExchange(CDataExchange* pDX) override; // 0x005dee80 (empty body)

  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
  afx_msg void OnRButtonDown(UINT nFlags, CPoint point);
  afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
  afx_msg void OnNcPaint();
  afx_msg void OnPaint();

  DECLARE_MESSAGE_MAP() // GetMessageMap 0x005deea0 (vtable index 12)
};

ASSERT_SIZE(TE0TemplateDialog, 0x74);

void ShowBlockingWaitOverlayDialog(void);

// VTABLE: IMPERIALISM 0x00647428
class TGameSetupOptionsDialog : public CDialog {
public:
  // FUNCTION: IMPERIALISM 0x004814b0
  ~TGameSetupOptionsDialog() override {}
  TGameSetupOptionsDialog(void* initParam);
  void SetGameSetupValues(GameSetup* setup);

  CSliderCtrl slider5c;
  CSliderCtrl slider98;
  CSliderCtrl sliderD4;
  int check110; // DDX_Check control 0x404
  int check114; // DDX_Check control 0x405
  GameSetup* state118;

protected:
  BOOL OnInitDialog() override;
  void OnOK() override;
  void DoDataExchange(CDataExchange* pDX) override;
  afx_msg void OnDoubleClickedOk(); // 0x004822e0 (BN_DOUBLECLICKED, IDOK)
  DECLARE_MESSAGE_MAP()             // GetMessageMap 0x004815d0 (vtable index 12)
};

ASSERT_SIZE(TGameSetupOptionsDialog, 0x11c);
