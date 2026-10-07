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
  virtual ~TWindow() override;
  virtual void Free() override;
  virtual TObject* ShallowClone() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual TWindow* GetWindow() override;
  virtual CWnd* Open() override;
  virtual void Close() override;
  virtual TView* GetRootView() override;
  virtual bool IsActionable() override;
  virtual void TranslateRectToWindow(CRect* rect) override;
  virtual void LocalToWindow(CPoint* point = 0) override;
  virtual void TranslatePointToParentChain4E(CPoint* point) override;
  virtual short ContainsMouse(const CPoint& point) override;
  virtual void GoAwayByUser(const CPoint& point) override;
  virtual void MoveByUser(const CPoint& point) override;
  virtual void ResizeByUser(const CPoint& point) override;
  virtual void ZoomByUser(const CPoint& point, short partCode) override;
  virtual void WindowToLocal(CPoint* point) override;
  virtual void SetModality(bool modal);
  virtual void SetDialogItems(unsigned long defaultCommandCode, unsigned long cancelCommandCode);
  virtual bool IsModal();
  virtual int PoseModally();
  virtual bool IsDismissed();
  virtual void Dismiss(unsigned long commandCode, bool accepted);
  virtual TDialogBehavior* GetDialogBehavior();
  virtual void AssertMcAppUILine2554();
  // Switching notifies the previous and new targets through TEventHandler slots.
  virtual void SetWindowTarget(TEventHandler* target);
  virtual void Center(bool centerX, bool centerY, bool unused);
  virtual void Activate(unsigned char active);
  virtual void Show(unsigned char show, bool refresh);
  // MacApp TWindow::CloseAndFree(): Close (slot 0x28) then Free (slot 0x07).
  virtual void CloseAndFree();
  virtual void SetTitle(const CString* title);
  virtual void GetTitle(CString* title);

  short windowStyleType; // window-type code; selects the CreateEx style bits
  unsigned char padding_62_to_63[0x02];
  TEventHandler* activeLinkedWindow;
  int activeViewTag; // child controlTag installed by tactical views
  bool resourceFlag6c;
  bool useCaptionedFrameFlag;
  bool resourceFlag6e;
  bool resourceFlag6f;
  bool topmostFlag; // when set, CMcWindow adds WS_EX_TOPMOST
  bool resourceFlag;
  unsigned char padding_72_to_73[0x02];
  TDialogBehavior dialogBehavior;
  int busyFlag;
  unsigned short windowFlags; // flag word set by the dialog factory builders
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
  dialogBehavior.IDialogBehavior(true, kControlTagSpSpSpSp, kControlTagSpSpSpSp);
  activeLinkedWindow = this;
  dialogBehavior.SetOwner(this);
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
