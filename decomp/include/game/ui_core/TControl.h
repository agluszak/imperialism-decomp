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
  short fontFamily;     // font-family index (CreateFontFromPresetAndAttachRegionHandle);
                        // 3 when fontSize < 12, else 1
  short fontStyleFlags; // bold/italic/underline bits
  short fontSize;       // font size or size index
  COLORREF textColor;   // Win32/MFC text color, including PALETTEINDEX values
};
#pragma pack(pop)

// VTABLE: IMPERIALISM 0x64a098
class TControl : public TView {
public:
  virtual ~TControl() override;
  virtual char PointInBoundsAndActionable(CPoint* point) override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag);
  virtual void BuildInsetContentRect(CRect* boundsBuffer);
  virtual void AssertCityProductionGlobalStateInitialized(int arg1, int arg2);
  virtual void NoOpUiViewSlotHandler(int arg1, int arg2);
  virtual void NoOpControlAction(int unusedArg);
  virtual void InstallTextStyle(const TextStyle& style, char refreshNow);
  virtual void SetTextColorAndMaybeRefresh(const COLORREF* textColor, bool refreshNow);
  virtual bool LogUnhandledDialogMethodAndReturnFalse();
  virtual void HiliteState(unsigned char enabledState, bool refreshNow);
  void SetDiplomacyNationSelectionFilterAndRefreshRows(short selectedNation);

  int eventNumber;
  unsigned char controlState;
  CRect contentInsets; // left/top/right/bottom content insets
                       // (BuildInsetContentRect, TStaticText/TTEView::Draw)
  TextStyle textStyle;

  TControl();
  TControl(const TControl& source)
      : TView(source), eventNumber(source.eventNumber), controlState(source.controlState),
        contentInsets(source.contentInsets), textStyle(source.textStyle) {}
  DECLARE_DYNCREATE(TControl)
  TObject* ShallowClone() override;
  void SetEventNumber(int value);

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual int GetEventNumber() override;
};

ASSERT_SIZE(TControl, 0x84);
