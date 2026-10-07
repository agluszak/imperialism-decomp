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
  TUiStyleBytes* Reset(); // 0x41b420 — same zeroing, out-of-line (thiscall, returns this)
  int packedColor;        // +0
  int styleWord;          // +4
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
  class TView* ownerContext; // 0x20
  int ownerLocalX;           // 0x24
  int ownerLocalY;           // 0x28
  int absoluteX;
  int absoluteY;
  int frameWidth;
  int frameHeight;
  int controlValue;
  TView* resourceContext;      // 0x40
  TViewChildList* childList;   // 0x44 — child-control list (CList<TView*,TView*>)
  TUiStyleBytes* stylePayload; // 8-byte style/color payload (see TUiStyleBytes above)
  bool inputGateFlag;
  bool childHitTestFlag;
  unsigned short cursorId;
  CWnd* nativeWindow; // 0x50 — host window (MFC CWnd; HWND via m_hWnd)
  unsigned short helpState;
  unsigned char padding_56_to_57[0x02];
  CString hoverHelpText;
  int hoverHelpEnabled;

  TView();
  TView(const TView& source); // 0x48bd30
  void InitializeUiResourceEntryFrameAndParent(TView* resourceContext, TView* panel,
                                               int* offsetLayout, int* sizeLayout, int layoutParam6,
                                               int layoutParam7, int attachFlag);
  void InvalidateCityDialogRectRegion(RECT* rect, int flag);
  void CopyViewStateFromSource(TView* source);
  void SetHoverHelpText(const CString& sharedString);
  void PropagateUiResourceContextRecursive(CWnd* nativeWindow);

  // Base-slot overrides (vtable bodies differ from TEventHandler's).
  DECLARE_DYNCREATE(TView)
  void Free() override;                  // 0x07
  TObject* ShallowClone() override;      // 0x08 0x48bfd0
  virtual TWindow* GetWindow() override; // 0x16 0x48b180

  virtual class TView* FindSubView(unsigned int controlTag);   // 0x25 0x48afd0
  virtual void SwitchActiveChildAndNotify(class TView* child); // 0x26 0x48af80
  virtual CWnd* Open();                                        // 0x27 0x48c820
  virtual void Close();                                        // 0x28 0x48c890
  virtual void Show(int show, int refreshNow);                 // 0x29 0x48b1c0; Mac name oracle
  virtual void ViewEnable(int enabled, int refreshNow);        // 0x2a 0x48b070; Mac name oracle
  virtual unsigned short GetCursorID();                        // 0x2b 0x427200
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg);   // 0x2c
  virtual void HandleHelp(const CPoint* point, RgnHandle helpRegion); // 0x2d 0x48c1c0
  virtual void GetDrawableRegion(RgnHandle region);                   // 0x2e 0x48c1e0
  virtual int GetEventNumber();                                       // 0x2f
  virtual void InvalidateRegion(RgnHandle region);                    // 0x30 0x48b4b0
  virtual void ForwardMapViewVirtualC4IfPresent(RgnHandle region);    // 0x31 0x48ab90
  virtual void ValidateVRect(RECT* rect);                             // 0x32 0x48b690
  virtual bool EvaluateControlInputGate();                            // 0x33 0x48c000
  virtual bool HasRenderableParentAndContent();                       // 0x34 0x48c050
  virtual void
  HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                      RgnHandle hitArg); // 0x35 0x48c080
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);      // 0x36 0x48aaf0
  virtual void DoPostCreate(int arg);                                    // 0x37 0x48ab70
  virtual void NoOpUiCallback();                                         // 0x38 0x48abc0
  virtual void RefreshControl();                                         // 0x39 0x48b6d0
  virtual TView* GetRootView();                                          // 0x3a 0x48b1a0
  virtual bool IsActionable();                                           // 0x3b 0x48b200
  virtual void Locate(const CPoint& position, bool refresh);             // 0x3c 0x48b250
  virtual void Resize(const CPoint& size, bool refresh);                 // 0x3d 0x48b3f0
  virtual bool PrepareForDrawing();                                      // 0x3e 0x48b770
  virtual void PostRender();                                             // 0x3f
  virtual int BindMapQuickDrawDc(CDC* paintDc);                          // 0x40 0x48b7b0
  virtual void ReleaseMapQuickDrawDc(CDC* paintDc);                      // 0x41 0x48b7e0
  virtual void EnsureStylePayload();                                     // 0x42 0x48b810
  virtual void PaintVisibleChildrenIntersectingClipRect(RECT* clipRect,
                                                        CDC* paintDc); // 0x43 0x48b8d0
  virtual void Draw(RECT* clipRect);                                   // 0x44
  virtual void PaintOrInvalidateControl(CDC* paintDc = 0);             // 0x45
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin); // 0x46 0x48c450
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin); // 0x47
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin); // 0x48 0x48c590
  virtual void HandleMouseCommandToSelf(CPoint& point, TToolboxEvent* event,
                                        CPoint origin);      // 0x49
  virtual void GetExtent(CRect* boundsOut);                  // 0x4a 0x427260
  virtual void GetFrame(CRect* boundsOut);                   // 0x4b 0x427290
  virtual void TranslateRectToWindow(CRect* rect);           // 0x4c 0x4272d0
  virtual void LocalToWindow(CPoint* point = 0);             // 0x4d 0x48ba80
  virtual void TranslatePointToParentChain4E(CPoint* point); // 0x4e 0x48ba40
  virtual void ForceRedraw();                                // 0x4f 0x48b700
  virtual void LocalToSuperVRect(CRect* rect);               // 0x50 0x48bb00
  virtual void SuperToLocal(CPoint* point);                  // 0x51
  virtual CPoint ViewToQDPt(CPoint* inPoint);
  virtual CRect ViewToQDRect(CRect* inRect);
  virtual void AddControlPosToPoint(int x, int y, CPoint* outPoint);
  virtual void OffsetRectByCachedPos(CRect* inRect, CRect* outRect);
  virtual CPoint* GetAbsolutePosition(CPoint* outPoint);
  virtual void GetDrawableQDRect(CRect* rectOut); // 0x57 0x429410
  virtual CRect* GetQDExtent(CRect* rectOut);
  virtual void UpdateCoordinates();
  virtual void SetFrame(CRect* newBounds, bool modeFlag);        // 0x5a 0x48c380
  virtual char PointInBoundsAndActionable(CPoint* point);        // 0x5b 0x48c6d0
  virtual void AttachChildControl(class TView* child, int flag); // 0x5c 0x48abe0
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
