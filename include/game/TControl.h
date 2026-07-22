#pragma once

#include "game/TView.h"

// Mac CodeWarrior names the shared capture callback TrackMouse and gives its first
// argument this phase type. Windows passes the same 0/1/2 begin/update/end values.
enum TrackPhase { kTrackPhaseBegin = 0, kTrackPhaseUpdate = 1, kTrackPhaseEnd = 2 };

// 10-byte packed text-style descriptor: three shorts plus a COLORREF-bearing text-color
// field at offset 6, as built by BuildUiTextStyleDescriptor (0x5c3e80) and
// BindUiResourceTextAndStyle (0x41b490). This is a reusable UI value type, not
// TControl-specific storage -- TTextLine independently embeds the identical 10-byte
// layout at its own +0x14 (styleDescriptor14).
#pragma pack(push, 2)
struct TextStyle {
  short fontFamily;     // 0x0 -- font-family index (CreateFontFromPresetAndAttachRegionHandle);
                        // 3 when fontSize < 12, else 1
  short fontStyleFlags; // 0x2 -- bold/italic/underline bits
  short fontSize;       // 0x4 -- font size or size index
  COLORREF textColor;   // 0x6 -- Win32/MFC text color, including PALETTEINDEX values
};
#pragma pack(pop)

// VTABLE: IMPERIALISM 0x64a098
class TControl : public TView {
public:
  virtual ~TControl() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IsEnabled inherited unchanged (0x48a240)
  // slot 0x0b SetEnable inherited unchanged (0x48a260)
  // slot 0x0c GetNextHandler inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f DoEvent override declared below (0x48e710)
  // slot 0x10 HandleEvent inherited unchanged (0x48a2e0)
  // slot 0x11 DoMenuCommand inherited unchanged (0x48a310)
  // slot 0x12 DoKeyEvent inherited unchanged (0x48a380)
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetIdleFreq inherited unchanged (0x415d50)
  // slot 0x15 SetIdleFreq inherited unchanged (0x415d70)
  // slot 0x16 GetWindow inherited unchanged (0x48b180)
  // slot 0x17 WantsToBeTarget inherited unchanged (0x48a530)
  // slot 0x18 WillingToResignTarget inherited unchanged (0x48a550)
  // slot 0x19 ResignedTarget inherited unchanged (0x48a690)
  // slot 0x1a TargetValidationFailed inherited unchanged (0x48a6b0)
  // slot 0x1b TargetValidationSucceeded inherited unchanged (0x48a650)
  // slot 0x1c BecameWindowTarget inherited unchanged (0x48a6d0)
  // slot 0x1d ResignedWindowTarget inherited unchanged (0x48a670)
  // slot 0x1e BecameTarget inherited unchanged (0x48a6f0)
  // slot 0x1f BecomeTarget inherited unchanged (0x48a570)
  // slot 0x20 ResignTarget inherited unchanged (0x48a5e0)
  // slot 0x21 SelectOwner inherited unchanged (0x48a710)
  // slot 0x22 IsTarget inherited unchanged (0x48a500)
  // slot 0x23 RemoveBehavior inherited unchanged (0x48a4a0)
  // slot 0x24 AddBehavior inherited unchanged (0x48a4d0)
  // slot 0x25 ResolveControlByTag inherited unchanged (0x48afd0)
  // slot 0x26 SwitchActiveChildAndNotify inherited unchanged (0x48af80)
  // slot 0x27 Open inherited unchanged (0x48c820)
  // slot 0x28 Close inherited unchanged (0x48c890)
  // slot 0x29 SetEnabled inherited unchanged (0x48b1c0)
  // slot 0x2a SetState inherited unchanged (0x48b070)
  // slot 0x2b GetField4E inherited unchanged (0x427200)
  // slot 0x2c DoSetCursor inherited unchanged (0x48c250)
  // slot 0x2d HandleHelp inherited unchanged (0x48c1c0)
  // slot 0x2e GetDrawableRegion inherited unchanged (0x48c1e0)
  // slot 0x30 InvalidateOffsetRegionUsingChildClipRect inherited unchanged (0x48b4b0)
  // slot 0x31 ForwardMapViewVirtualC4IfPresent inherited unchanged (0x48ab90)
  // slot 0x32 ValidateControlRectIfWindowActive inherited unchanged (0x48b690)
  // slot 0x33 EvaluateControlInputGate inherited unchanged (0x48c000)
  // slot 0x34 HasRenderableParentAndContent inherited unchanged (0x48c050)
  // slot 0x35 HandleCursorHoverSelectionByChildHitTestAndFallback inherited unchanged (0x48c080)
  // slot 0x36 DispatchControlEventToChildrenAndSelf inherited unchanged (0x48aaf0)
  // slot 0x37 DoPostCreate inherited unchanged (0x48ab70)
  // slot 0x38 NoOpUiCallback inherited unchanged (0x48abc0)
  // slot 0x39 RefreshControl inherited unchanged (0x48b6d0)
  // slot 0x3a GetRootView inherited unchanged (0x48b1a0)
  // slot 0x3b IsActionable inherited unchanged (0x48b200)
  // slot 0x3c CaptureLayoutF0 inherited unchanged (0x48b250)
  // slot 0x3d CaptureLayout inherited unchanged (0x48b3f0)
  // slot 0x3e Refresh inherited unchanged (0x48b770)
  // slot 0x3f PostRender inherited unchanged (0x427220)
  // slot 0x40 BindMapQuickDrawDc inherited unchanged (0x48b7b0)
  // slot 0x41 ReleaseMapQuickDrawDc inherited unchanged (0x48b7e0)
  // slot 0x42 EnsureField48Buffer inherited unchanged (0x48b810)
  // slot 0x43 PaintVisibleChildrenIntersectingClipRect inherited unchanged (0x48b8d0)
  // slot 0x44 Draw inherited unchanged (0x430bf0)
  // slot 0x45 PaintOrInvalidateControl inherited unchanged (0x48b860)
  // slot 0x46 HandleMouseDown inherited unchanged (0x48c450)
  // slot 0x48 HandleMouseUp inherited unchanged (0x48c590)
  // slot 0x49 HandleMouseCommandToSelf inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c TranslateRectToWindow inherited unchanged (0x4272d0)
  // slot 0x4d TranslatePointToParentChain4D inherited unchanged (0x48ba80)
  // slot 0x4e TranslatePointToParentChain4E inherited unchanged (0x48ba40)
  // slot 0x4f ForceRedraw inherited unchanged (0x48b700)
  // slot 0x50 LocalToSuperVRect inherited unchanged (0x48bb00)
  // slot 0x51 SuperToLocal inherited unchanged (0x427330)
  // slot 0x52 ViewToQDPt inherited unchanged (0x48bb60)
  // slot 0x53 ViewToQDRect inherited unchanged (0x48bbb0)
  // slot 0x54 AddControlPosToPoint inherited unchanged (0x48bc30)
  // slot 0x55 OffsetRectByCachedPos inherited unchanged (0x48bc60)
  // slot 0x56 GetAbsolutePosition inherited unchanged (0x48bb30)
  // slot 0x57 GetDrawableQDRect inherited unchanged (0x429410)
  // slot 0x58 GetQDExtent inherited unchanged (0x48bce0)
  // slot 0x59 UpdateCoordinates inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  virtual char PointInBoundsAndActionable(CPoint* point) override; // slot 0x5b 0x48e940
  // slot 0x5c AttachChildControl inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e GetHelpState inherited unchanged (0x48c970)
  // slot 0x5f ContainsMouse inherited unchanged (0x48c990)
  // slot 0x60 GoAwayByUser inherited unchanged (0x48c9e0)
  // slot 0x61 MoveByUser inherited unchanged (0x48ca00)
  // slot 0x62 ResizeByUser inherited unchanged (0x48ca20)
  // slot 0x63 ZoomByUser inherited unchanged (0x48ca40)
  // slot 0x64 DrawRectangleInCurrentUiContext inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922 inherited unchanged (0x48c7d0)
  // slot 0x67 WindowToLocal inherited unchanged (0x48bac0)
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag); // slot 0x68 0x48e850
  // Build this control's content bounds (via QueryContentBounds) then deflate by
  // contentInsets68 -- the shared "content rect with margins applied" primitive used by
  // Draw-family paint code. Some subclasses (e.g. TCivDescription) repurpose
  // this vtable slot for an unrelated override rather than this semantic.
  virtual void BuildInsetContentRect(CRect* boundsBuffer); // slot 0x69 0x48e980
  virtual void AssertCityProductionGlobalStateInitialized(int arg1,
                                                          int arg2); // slot 0x6a 0x429470
  virtual void NoOpUiViewSlotHandler(int arg1, int arg2);            // slot 0x6b 0x48e9c0
  // One ignored stack arg (bare RET 0x4). This TControl slot is unrelated to the
  // byte-coincident TPageView::ShowPage slot on the sibling TView hierarchy.
  virtual void NoOpControlAction(int unusedArg); // slot 0x6c 0x48e9e0
  virtual void InstallTextStyle(const TextStyle& style,
                                char refreshNow); // slot 0x6d 0x48e7d0
  virtual void SetTextColorAndMaybeRefresh(const COLORREF* textColor,
                                           bool refreshNow); // slot 0x6e 0x48e7a0
  virtual char LogUnhandledDialogMethodAndReturnFalse();     // slot 0x6f 0x4294a0
  virtual void HiliteState(unsigned char enabledState,
                           unsigned char refreshNow); // slot 0x70 0x48e810
  void SetDiplomacyNationSelectionFilterAndRefreshRows(short selectedNation);

  // 0x60 -- command/event number returned by GetEventNumber and dispatched by DoEvent.
  // Observed values include 4, 5, 6, 0xa, 0xc, 0xd, and 0x22.
  int eventNumber60;
  // 0x64 -- enabled/mode state byte: HiliteState's enabledState;
  // THQButton/TUpDownPictureButton also drive a multi-valued "mode" through it.
  unsigned char controlState64;
  unsigned char padding_65_to_67[3];
  CRect contentInsets68; // 0x68-0x77 -- left/top/right/bottom content insets
                         // (BuildInsetContentRect, TStaticText/TTEView::Draw)
  TextStyle textStyle78; // 0x78-0x81

  TControl();
  DECLARE_DYNCREATE(TControl)
  // Slot 0x08 override (0x00435760): controls cannot be cloned (no engineer-dialog
  // state); assert via the McAppUI invalidation thunk and return null.
  TObject* ShallowClone() override;
  void SetEventNumber(int value);

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // 0x0f 0x48e710
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual int GetEventNumber() override;

  // Not yet ported (0x5be150, 420 bytes) -- called by TOfferDeskPicture::DoEvent with a
  // lookup-table-derived selection index; body left as an honest stub pending investigation.
  void UpdateSelectionRect(short selectionIndex);
};

ASSERT_SIZE(TControl, 0x84);
