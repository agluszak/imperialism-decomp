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

//
// TView inherits the 37-slot shared interface (slots 0x00-0x24) and fields through +0x1c
// from TEventHandler. It overrides only the few base slots whose vtable bodies differ
// (0x07 ReleaseRuntimeSelectionOwnerAndDestroyObject, 0x08 CloneEngineerDialogStateToNewInstance,
// 0x16 GetWindow) and introduces its own virtuals at slot 0x25+ (declared below in exact vtable
// slot order). See game/ui_core/TEventHandler.h.

// 8-byte style/color payload hung off TView::stylePayload48 (see TView::EnsureField48Buffer
// 0x48b810 and ReplaceUiResourceContextPairBuffer 0x427060). Its default ctor zeroes
// the bytes and is inlined at the new-expressions (both bodies show the 8 byte-stores
// inline); factory builders call the equivalent out-of-line Reset entry at 0x41b420.
// packedColor/styleWord names are hedged from the observed writes ({0xffffff, 0} at
// the 0x427060 call sites).
class TUiStyleBytes {
public:
  // Inline default ctor: zero the 8 style bytes byte-wise. Inlined at the
  // new-expressions in TView::EnsureField48Buffer (0x48b810) and
  // ReplaceUiResourceContextPairBuffer (0x427060); the factory-builder TUs call the
  // out-of-line Reset body (0x41b420) instead.
  TUiStyleBytes() {
    styleBytes[0] = 0;
    styleBytes[1] = 0;
    styleBytes[2] = 0;
    styleBytes[3] = 0;
    styleBytes[4] = 0;
    styleBytes[5] = 0;
    styleBytes[6] = 0;
    styleBytes[7] = 0;
  }
  TUiStyleBytes* Reset(); // 0x41b420 — same zeroing, out-of-line (thiscall, returns this)
  union {
    unsigned char styleBytes[8];
    struct {
      int packedColor; // +0
      int styleWord;   // +4
    };
  };
};

// Typed MFC child list used by TView::childList44. The two non-virtual helpers are
// carried by the retail binary immediately before TEventHandler's RTTI factory;
// their receiver layout and element access prove they belong to this list, not to
// TEventHandler itself.
class TViewChildList : public CList<TView*, TView*> {
public:
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
  // 0x34/0x38 — control frame size; CMcWindow builds the native window rect as
  // (ownerLocalX, ownerLocalY) + frameWidth34 x frameHeight38.
  int frameWidth34;
  int frameHeight38;
  // 0x3c — general per-control value slot: toggle/current value (T2PictToggleButton),
  // window id (TDisplayMgr), dialog resource-template id (TControl).
  int controlValue3c;
  // Optional resource-construction context inherited by dynamically built child views.
  // Controls that do not inherit a context store null here.
  TView* resourceContext;        // 0x40
  TViewChildList* childList44;   // 0x44 — child-control list (CList<TView*,TView*>)
  TUiStyleBytes* stylePayload48; // 8-byte style/color payload (see TUiStyleBytes above)
  // 0x4c — participates in the control input gate (EvaluateControlInputGate passes
  // when this is set and IsEnabled() reports true).
  bool inputGateFlag4c;
  // 0x4d — gates child traversal for renderability/hover hit-tests
  // (HasRenderableParentAndContent requires it before childList44 counts).
  bool childHitTestFlag4d;
  unsigned short cursorId4e;
  CWnd* nativeWindow50; // 0x50 — host window (MFC CWnd; HWND via m_hWnd)
  unsigned short helpState54;
  unsigned char padding_56_to_57[0x02];
  CString hoverHelpText58;
  int hoverHelpEnabled5c;

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

  // TView-introduced virtuals (slots 0x25-0x67), in exact vtable slot order. Slot
  // assignments are pinned by FUNCTION-marker addresses, original-binary call offsets,
  // and the corresponding Mac-oracle method signatures where available.
  virtual class TView* ResolveControlByTag(unsigned int controlTag);       // 0x25 0x48afd0
  virtual void SwitchActiveChildAndNotify(class TView* child);             // 0x26 0x48af80
  virtual CWnd* Open();                                                    // 0x27 0x48c820
  virtual void Close();                                                    // 0x28 0x48c890
  virtual void SetEnabled(int enabledState, int refreshFlag);              // 0x29 0x48b1c0
  virtual void SetState(int state, int refreshFlag);                       // 0x2a 0x48b070
  virtual unsigned short GetCursorID();                                    // 0x2b 0x427200
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg);               // 0x2c
  virtual void HandleHelp(const CPoint* point, RgnHandle helpRegion);      // 0x2d 0x48c1c0
  virtual void GetDrawableRegion(RgnHandle region);                        // 0x2e 0x48c1e0
  virtual int GetEventNumber();                                            // 0x2f
  virtual void InvalidateOffsetRegionUsingChildClipRect(RgnHandle region); // 0x30 0x48b4b0
  virtual void ForwardMapViewVirtualC4IfPresent(RgnHandle region);         // 0x31 0x48ab90
  virtual void ValidateControlRectIfWindowActive(RECT* rect);              // 0x32 0x48b690
  virtual char EvaluateControlInputGate();                                 // 0x33 0x48c000
  virtual char HasRenderableParentAndContent();                            // 0x34 0x48c050
  virtual void
  HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                      RgnHandle hitArg); // 0x35 0x48c080
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);      // 0x36 0x48aaf0
  virtual void DoPostCreate(int arg);                                    // 0x37 0x48ab70
  virtual void NoOpUiCallback();                                         // 0x38 0x48abc0
  virtual void RefreshControl();                                         // 0x39 0x48b6d0
  virtual TView* GetRootView();                                          // 0x3a 0x48b1a0
  virtual bool IsActionable();                                           // 0x3b 0x48b200
  virtual void Locate(const CPoint& position, unsigned char refresh);    // 0x3c 0x48b250
  virtual void Resize(const CPoint& size, unsigned char refresh);        // 0x3d 0x48b3f0
  virtual char PrepareForDrawing();                                      // 0x3e 0x48b770
  virtual void PostRender();                                             // 0x3f
  // The "DC handle" flowing through slots 0x40/0x41/0x43/0x45 is a caller-supplied MFC
  // CDC* (or null = bind a fresh window DC): CMcWindow::OnPaint (0x4938c0) passes its
  // CPaintDC here, and BindScopedMapQuickDrawDcHandle stores it as the active DC object.
  virtual int BindMapQuickDrawDc(CDC* paintDc);     // 0x40 0x48b7b0
  virtual void ReleaseMapQuickDrawDc(CDC* paintDc); // 0x41 0x48b7e0
  virtual void EnsureField48Buffer();               // 0x42 0x48b810
  virtual void PaintVisibleChildrenIntersectingClipRect(RECT* clipRect,
                                                        CDC* paintDc); // 0x43 0x48b8d0
  virtual void Draw(RECT* clipRect);                                   // 0x44
  virtual void PaintOrInvalidateControl(CDC* paintDc = 0);             // 0x45
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin); // 0x46 0x48c450
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin); // 0x47
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin); // 0x48 0x48c590
  virtual char HandleMouseCommandToSelf(CPoint& point, TToolboxEvent* event,
                                        CPoint origin);          // 0x49
  virtual void QueryContentBounds(CRect* boundsOut);             // 0x4a 0x427260
  virtual void QueryBounds(CRect* boundsOut);                    // 0x4b 0x427290
  virtual void TranslateRectToWindow(CRect* rect);               // 0x4c 0x4272d0
  virtual void TranslatePointToParentChain4D(CPoint* point = 0); // 0x4d 0x48ba80
  virtual void TranslatePointToParentChain4E(CPoint* point);     // 0x4e 0x48ba40
  virtual void ForceRedraw();                                    // 0x4f 0x48b700
  virtual void LocalToSuperVRect(CRect* rect);                   // 0x50 0x48bb00
  virtual void SuperToLocal(CPoint* point);                      // 0x51
  virtual CPoint ViewToQDPt(CPoint* inPoint);
  virtual CRect ViewToQDRect(CRect* inRect);
  virtual void AddControlPosToPoint(int x, int y, CPoint* outPoint);
  virtual void OffsetRectByCachedPos(CRect* inRect, CRect* outRect);
  virtual CPoint* GetAbsolutePosition(CPoint* outPoint);
  virtual void GetDrawableQDRect(CRect* rectOut); // 0x57 0x429410
  virtual CRect* GetQDExtent(CRect* rectOut);
  virtual void UpdateCoordinates();
  virtual void ApplyBounds(CRect* newBounds, unsigned char modeFlag); // 0x5a 0x48c380
  virtual char PointInBoundsAndActionable(CPoint* point);             // 0x5b 0x48c6d0
  virtual void AttachChildControl(class TView* child, int flag);      // 0x5c 0x48abe0
  virtual void DetachChildFromOwnerList(class TView* child);
  virtual unsigned short GetHelpState();
  virtual short ContainsMouse(const CPoint& point);
  virtual void GoAwayByUser(const CPoint& point);
  virtual void MoveByUser(const CPoint& point);
  virtual void ResizeByUser(const CPoint& point);
  virtual void ZoomByUser(const CPoint& point, short partCode);
  virtual void DrawRectangleInCurrentUiContext(const RECT* rect);
  // One ignored stack arg (body ends `RET 0x4`; sibling Line1922 is a bare RET)
  // -- present only for stack-cleanup fidelity.
  virtual void AssertMcAppUiLine1914(int unusedArg);
  virtual void AssertMcAppUiLine1922();
  virtual void WindowToLocal(CPoint* point);
  // TView's real vtable is 104 slots (0x00-0x19c). Slots 0x1A0+ belong to the sibling
  // branches (TControl, TCivDescription, TAmtBar, ...). The destructor is slot 1
  // (TEventHandler override), so its declaration position is irrelevant.
  //
  // MATCH: keep the destructor out-of-line; header inlining emits unwanted per-TU COMDATs
  // and lowers similarity in unrelated translation units.
  virtual ~TView() override;
};
ASSERT_SIZE(TView, 0x60);
