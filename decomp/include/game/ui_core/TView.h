#pragma once

#include <afxtempl.h>

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_core/TEventHandler.h"
#include "game/core/CString.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/mfc.h"

class CMcWindow;
struct TToolboxEvent;

// TView inherits TEventHandler's 37 shared slots and declares its own from slot 0x25.

class TUiStyleBytes {
public:
  TUiStyleBytes() : packedColor(0), styleWord(0) {}
  TUiStyleBytes* Reset(); // same zeroing, out-of-line (thiscall, returns this)
  int packedColor;
  int styleWord;
};

class TViewChildList : public CList<TView*, TView*> {
public:
  TView* FindByTag(unsigned int tag);
  void RemoveByTag(unsigned int tag);
  void FreeAll();
};

ASSERT_SIZE(TViewChildList, 0x1c);

// VTABLE: IMPERIALISM 0x649858
class TView : public TEventHandler {
public:
  class TView* ownerContext;
  int ownerLocalX;
  int ownerLocalY;
  int absoluteX;
  int absoluteY;
  int frameWidth;
  int frameHeight;
  int controlValue;
  TView* resourceContext;
  TViewChildList* childList;   // child-control list (CList<TView*,TView*>)
  TUiStyleBytes* stylePayload; // byte style/color payload (see TUiStyleBytes above)
  bool inputGateFlag;
  bool childHitTestFlag;
  unsigned short cursorId;
  CWnd* nativeWindow; // host window (MFC CWnd; HWND via m_hWnd)
  unsigned short helpState;
  unsigned char padding_56_to_57[0x02];
  CString hoverHelpText;
  int hoverHelpEnabled;

  TView();
  TView(const TView& source);
  void InitializeUiResourceEntryFrameAndParent(TView* resourceContext, TView* panel,
                                               int* offsetLayout, int* sizeLayout, int layoutParam6,
                                               int layoutParam7, int attachFlag);
  void InvalidateCityDialogRectRegion(RECT* rect, int flag);
  void CopyViewStateFromSource(TView* source);
  void SetHoverHelpText(const CString& sharedString);
  void PropagateUiResourceContextRecursive(CWnd* nativeWindow);

  // Base-slot overrides (vtable bodies differ from TEventHandler's).
  DECLARE_DYNCREATE(TView)
  void Free() override;
  TObject* ShallowClone() override;
  virtual TWindow* GetWindow() override;

  virtual class TView* FindSubView(unsigned int controlTag);
  virtual void SwitchActiveChildAndNotify(class TView* child);
  virtual CWnd* Open();
  virtual void Close();
  virtual void Show(int show, int refreshNow);          // Mac name oracle
  virtual void ViewEnable(int enabled, int refreshNow); // Mac name oracle
  virtual unsigned short GetCursorID();
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg);
  virtual void HandleHelp(const CPoint* point, RgnHandle helpRegion);
  virtual void GetDrawableRegion(RgnHandle region);
  virtual int GetEventNumber();
  virtual void InvalidateRegion(RgnHandle region);
  virtual void ForwardMapViewVirtualC4IfPresent(RgnHandle region);
  virtual void ValidateVRect(RECT* rect);
  virtual bool EvaluateControlInputGate();
  virtual bool HasRenderableParentAndContent();
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point, RgnHandle hitArg);
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);
  virtual void DoPostCreate(int arg);
  virtual void NoOpUiCallback();
  virtual void RefreshControl();
  virtual TView* GetRootView();
  virtual bool IsActionable();
  virtual void Locate(const CPoint& position, bool refresh);
  virtual void Resize(const CPoint& size, bool refresh);
  virtual bool PrepareForDrawing();
  virtual void PostRender();
  virtual int BindMapQuickDrawDc(CDC* paintDc);
  virtual void ReleaseMapQuickDrawDc(CDC* paintDc);
  virtual void EnsureStylePayload();
  virtual void PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc);
  virtual void Draw(RECT* clipRect);
  virtual void PaintOrInvalidateControl(CDC* paintDc = 0);
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin);
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin);
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin);
  virtual void HandleMouseCommandToSelf(CPoint& point, TToolboxEvent* event, CPoint origin);
  virtual void GetExtent(CRect* boundsOut);
  virtual void GetFrame(CRect* boundsOut);
  virtual void TranslateRectToWindow(CRect* rect);
  virtual void LocalToWindow(CPoint* point = 0);
  virtual void TranslatePointToParentChain4E(CPoint* point);
  virtual void ForceRedraw();
  virtual void LocalToSuperVRect(CRect* rect);
  virtual void SuperToLocal(CPoint* point);
  virtual CPoint ViewToQDPt(CPoint* inPoint);
  virtual CRect ViewToQDRect(CRect* inRect);
  virtual void AddControlPosToPoint(int x, int y, CPoint* outPoint);
  virtual void OffsetRectByCachedPos(CRect* inRect, CRect* outRect);
  virtual CPoint* GetAbsolutePosition(CPoint* outPoint);
  virtual void GetDrawableQDRect(CRect* rectOut);
  virtual CRect* GetQDExtent(CRect* rectOut);
  virtual void UpdateCoordinates();
  virtual void SetFrame(CRect* newBounds, bool modeFlag);
  virtual char PointInBoundsAndActionable(CPoint* point);
  virtual void AttachChildControl(class TView* child, int flag);
  virtual void RemoveSubView(class TView* child);
  virtual unsigned short GetHelpState();
  virtual short ContainsMouse(const CPoint& point);
  virtual void GoAwayByUser(const CPoint& point);
  virtual void MoveByUser(const CPoint& point);
  virtual void ResizeByUser(const CPoint& point);
  virtual void ZoomByUser(const CPoint& point, short partCode);
  virtual void DrawRectangleInCurrentUiContext(const RECT* rect);
  virtual void AssertMcAppUiLine1914(int unusedArg);
  virtual void AssertMcAppUiLine1922();
  virtual void WindowToLocal(CPoint* point);
  virtual ~TView() override;
};
ASSERT_SIZE(TView, 0x60);
