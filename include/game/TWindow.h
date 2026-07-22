#pragma once

#include "game/TDialogBehavior.h"
#include "game/TView.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TObject;

// VTABLE: IMPERIALISM 0x00649e58
class TWindow : public TView {
public:
  DECLARE_DYNCREATE(TWindow)
  virtual ~TWindow() override;              // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;             // slot 0x07 0x48e2a0
  virtual TObject* ShallowClone() override; // slot 0x08 0x492d80
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0048dd50
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event) override;                       // slot 0x10 0x48dd10
  virtual TWindow* GetWindow() override;                                  // slot 0x16 0x492cc0
  virtual CMcWindow* Open() override;                                     // slot 0x27 0x48de00
  virtual void Close() override;                                          // slot 0x28 0x48e060
  virtual TView* GetRootView() override;                                  // slot 0x3a 0x492ce0
  virtual char IsActionable() override;                                   // slot 0x3b 0x48d980
  virtual void TranslateRectToWindow(CRect* rect) override;               // slot 0x4c 0x492d40
  virtual void TranslatePointToParentChain4D(CPoint* point = 0) override; // slot 0x4d 0x492d20
  virtual void TranslatePointToParentChain4E(CPoint* point) override;     // slot 0x4e 0x492d00
  virtual short ContainsMouse(const CPoint& point) override;              // slot 0x5f 0x48e1c0
  virtual void GoAwayByUser(const CPoint& point) override;                // slot 0x60 0x48e1e0
  virtual void MoveByUser(const CPoint& point) override;                  // slot 0x61 0x48e210
  virtual void ResizeByUser(const CPoint& point) override;                // slot 0x62 0x48e240
  virtual void ZoomByUser(const CPoint& point, short partCode) override;  // slot 0x63 0x48e270
  virtual void WindowToLocal(CPoint* point) override;                     // slot 0x67 0x492d60
  virtual void SetModality(unsigned char modal);                          // slot 0x68 0x48da40
  virtual void SetDialogItems(unsigned long defaultCommandCode,
                              unsigned long cancelCommandCode); // slot 0x69 0x48d8a0
  virtual unsigned char IsModal();                              // slot 0x6a 0x48da10
  virtual int PoseModally();                                    // slot 0x6b 0x48da60
  virtual unsigned char IsDismissed();                          // slot 0x6c 0x48dc60
  // Forwards to GetDialogBehavior()'s own command-arming slot 0x0e (a no-op if
  // no behavior is attached), which stashes commandCode as armedCommandCode and
  // dispatches it to the behavior's owner. 0x48dc90.
  virtual void Dismiss(unsigned long commandCode,
                       unsigned char accepted); // slot 0x6d 0x48dc90
  virtual TDialogBehavior* GetDialogBehavior(); // slot 0x6e 0x48dcc0
  virtual void AssertMcAppUILine2554();         // slot 0x6f 0x48dce0
  // Switching notifies the previous and new targets through TEventHandler slots.
  virtual void SetWindowTarget(TEventHandler* target); // slot 0x70 0x48ddc0
  // Centers the real MFC CWnd (CenterWindow) when one is attached; otherwise computes
  // ownerLocalX/Y directly against the fixed 0x280x0x1e0 work area, per flag.
  virtual void Center(unsigned char centerX, unsigned char centerY,
                      unsigned char unused);                    // slot 0x71 0x48e150
  virtual void AssertMcAppUILine2358(int unusedArg);            // slot 0x72 0x48d8d0
  virtual void Show(unsigned char show, unsigned char refresh); // slot 0x73 0x48d900
  // MacApp TWindow::CloseAndFree(): Close (slot 0x28) then Free (slot 0x07).
  virtual void CloseAndFree();                 // slot 0x74 0x48e120
  virtual void SetTitle(const CString* title); // slot 0x75 0x48d9c0
  virtual void GetTitle(CString* title);       // slot 0x76 0x48d9f0

  // --- TWindow data members (object size 0xa0; the TView subobject ends at 0x60). ---
  // The 0x74 region is an embedded TDialogBehavior subobject (ConstructTDialogBehaviorBaseState
  // at +0x74). Remaining named fields are accessed directly by TWindow's own methods.
  // Offsets that are not yet attributed stay as padding.
  short windowStyleType; // 0x60 — window-type code; selects the CreateEx style bits
  unsigned char padding_62_to_63[0x02];
  // 0x64 — the currently-active linked window (init = this); switching targets
  // notifies the previous one via BecameWindowTarget.
  TEventHandler* activeLinkedWindow64;
  int activeViewTag68; // 0x68 — child controlTag installed by tactical views
  // 0x6c-0x71 — style/behavior booleans written by the UI resource builders. The names
  // remain offset-qualified where no Windows reader has established the exact behavior.
  bool resourceFlag6c; // 0x6c
  // 0x6d — for window-type codes 0x30/0x1f40, selects the captioned frame style
  // (0x00c80000) instead of the popup style (0x80c00000) in CMcWindow's CreateEx.
  bool useCaptionedFrameFlag6d;
  bool resourceFlag6e; // 0x6e
  bool resourceFlag6f; // 0x6f
  bool topmostFlag70;  // 0x70 — when set, CMcWindow adds WS_EX_TOPMOST
  bool resourceFlag71; // 0x71
  unsigned char padding_72_to_73[0x02];
  TDialogBehavior dialogBehavior; // 0x74
  int busyFlag98;                 // 0x98
  unsigned short windowFlags;     // 0x9c — flag word set by the dialog factory builders
  unsigned char padding_9e_to_9f[0x02];

  TWindow();
};
