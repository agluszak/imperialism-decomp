#pragma once

#include "game/ui_core/TView.h"

enum TrackPhase { kTrackPhaseBegin = 0, kTrackPhaseUpdate = 1, kTrackPhaseEnd = 2 };

enum ControlHiliteCommand {
  kControlCommandHiliteOn = 0x1f,
  kControlCommandHiliteOff = 0x20,
  kControlCommandHiliteToggle = 0x21
};

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
                          bool commandFlag);               // slot 0x68 0x48e850
  virtual void BuildInsetContentRect(CRect* boundsBuffer); // slot 0x69 0x48e980
  virtual void AssertCityProductionGlobalStateInitialized(int arg1,
                                                          int arg2); // slot 0x6a 0x429470
  virtual void NoOpUiViewSlotHandler(int arg1, int arg2);            // slot 0x6b 0x48e9c0
  virtual void NoOpControlAction(int unusedArg);                     // slot 0x6c 0x48e9e0
  virtual void InstallTextStyle(const TextStyle& style,
                                char refreshNow); // slot 0x6d 0x48e7d0
  virtual void SetTextColorAndMaybeRefresh(const COLORREF* textColor,
                                           bool refreshNow); // slot 0x6e 0x48e7a0
  virtual bool LogUnhandledDialogMethodAndReturnFalse();     // slot 0x6f 0x4294a0
  virtual void HiliteState(unsigned char enabledState,
                           bool refreshNow); // slot 0x70 0x48e810
  void SetDiplomacyNationSelectionFilterAndRefreshRows(short selectedNation);

  int eventNumber;
  unsigned char controlState;
  CRect contentInsets; // 0x68-0x77 -- left/top/right/bottom content insets
                       // (BuildInsetContentRect, TStaticText/TTEView::Draw)
  TextStyle textStyle; // 0x78-0x81

  TControl();
  TControl(const TControl& source)
      : TView(source), eventNumber(source.eventNumber), controlState(source.controlState),
        contentInsets(source.contentInsets), textStyle(source.textStyle) {}
  DECLARE_DYNCREATE(TControl)
  TObject* ShallowClone() override;
  void SetEventNumber(int value);

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // 0x0f 0x48e710
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual int GetEventNumber() override;
};

ASSERT_SIZE(TControl, 0x84);
