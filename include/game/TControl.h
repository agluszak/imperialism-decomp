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
  // slot 0x0f DoEvent override declared below (0x48e710)
  virtual char PointInBoundsAndActionable(CPoint* point) override; // slot 0x5b 0x48e940
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
