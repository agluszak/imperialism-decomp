#pragma once

#include "compat.h"

#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TObject;

#if defined(__clang__)
#pragma clang diagnostic push
// Windows retains TView::Show(int, int) at slot 0x29 and adds this byte overload at 0x73.
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

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
  virtual CWnd* Open() override;                                          // slot 0x27 0x48de00
  virtual void Close() override;                                          // slot 0x28 0x48e060
  virtual TView* GetRootView() override;                                  // slot 0x3a 0x492ce0
  virtual bool IsActionable() override;                                   // slot 0x3b 0x48d980
  virtual void TranslateRectToWindow(CRect* rect) override;               // slot 0x4c 0x492d40
  virtual void TranslatePointToParentChain4D(CPoint* point = 0) override; // slot 0x4d 0x492d20
  virtual void TranslatePointToParentChain4E(CPoint* point) override;     // slot 0x4e 0x492d00
  virtual short ContainsMouse(const CPoint& point) override;              // slot 0x5f 0x48e1c0
  virtual void GoAwayByUser(const CPoint& point) override;                // slot 0x60 0x48e1e0
  virtual void MoveByUser(const CPoint& point) override;                  // slot 0x61 0x48e210
  virtual void ResizeByUser(const CPoint& point) override;                // slot 0x62 0x48e240
  virtual void ZoomByUser(const CPoint& point, short partCode) override;  // slot 0x63 0x48e270
  virtual void WindowToLocal(CPoint* point) override;                     // slot 0x67 0x492d60
  virtual void SetModality(bool modal);                                   // slot 0x68 0x48da40
  virtual void SetDialogItems(unsigned long defaultCommandCode,
                              unsigned long cancelCommandCode); // slot 0x69 0x48d8a0
  virtual unsigned char IsModal();                              // slot 0x6a 0x48da10
  virtual int PoseModally();                                    // slot 0x6b 0x48da60
  virtual unsigned char IsDismissed();                          // slot 0x6c 0x48dc60
  virtual void Dismiss(unsigned long commandCode,
                       bool accepted);          // slot 0x6d 0x48dc90
  virtual TDialogBehavior* GetDialogBehavior(); // slot 0x6e 0x48dcc0
  virtual void AssertMcAppUILine2554();         // slot 0x6f 0x48dce0
  // Switching notifies the previous and new targets through TEventHandler slots.
  virtual void SetWindowTarget(TEventHandler* target); // slot 0x70 0x48ddc0
  virtual void Center(bool centerX, bool centerY,
                      bool unused);                    // slot 0x71 0x48e150
  virtual void Activate(unsigned char active);         // slot 0x72 0x48d8d0
  virtual void Show(unsigned char show, bool refresh); // slot 0x73 0x48d900
  // MacApp TWindow::CloseAndFree(): Close (slot 0x28) then Free (slot 0x07).
  virtual void CloseAndFree();                 // slot 0x74 0x48e120
  virtual void SetTitle(const CString* title); // slot 0x75 0x48d9c0
  virtual void GetTitle(CString* title);       // slot 0x76 0x48d9f0

  short windowStyleType; // 0x60 — window-type code; selects the CreateEx style bits
  unsigned char padding_62_to_63[0x02];
  TEventHandler* activeLinkedWindow;
  int activeViewTag; // 0x68 — child controlTag installed by tactical views
  bool resourceFlag6c; // 0x6c
  bool useCaptionedFrameFlag;
  bool resourceFlag6e; // 0x6e
  bool resourceFlag6f; // 0x6f
  bool topmostFlag;    // 0x70 — when set, CMcWindow adds WS_EX_TOPMOST
  bool resourceFlag71; // 0x71
  unsigned char padding_72_to_73[0x02];
  TDialogBehavior dialogBehavior; // 0x74
  int busyFlag;                   // 0x98
  unsigned short windowFlags;     // 0x9c — flag word set by the dialog factory builders
  unsigned char padding_9e_to_9f[0x02];

  TWindow();
};
ASSERT_SIZE(TWindow, 0xa0);

extern CList<TWindow*, TWindow*> g_LiveViewRegistry;
// Modal-window stack (base 0x006a1ac0): pushed on modal entry, popped on exit.
extern CList<TWindow*, TWindow*> g_ModalViewStack;

// FUNCTION: IMPERIALISM 0x0048d500
inline TWindow::TWindow() : TView(), dialogBehavior(), busyFlag(0) {
  g_LiveViewRegistry.AddHead(this);
  dialogBehavior.SetUiColorDescriptorGoldTriplet(true, kControlTagSpSpSpSp, kControlTagSpSpSpSp);
  activeLinkedWindow = this;
  dialogBehavior.SetOwner(this);
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
