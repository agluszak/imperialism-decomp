#pragma once

#include "game/ui_core/TControl.h"
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e4c0
class TTextLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTextLine)
  virtual ~TTextLine() override;
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  CString captionText;
  // Font/theme preset consumed by CreateFontFromPresetAndAttachRegionHandle et al.
  TextStyle styleDescriptor;
  // Passed directly to TStaticText::SetJustification.
  short textAlignmentCode;

  TTextLine();
  void ITextLine(short rowArg, short colArg, int* bounds, short styleGroupCode, short styleIndex);
  void SetTheTextStyle(const TextStyle* descriptor);
  void SetTextLineStyleComponents(short fontCode, short styleCode, short sizeCode,
                                  unsigned char red, unsigned char green, unsigned char blue);
  void SetTheJustification(short value);
  void SetCaptionText(CString* caption);
};

ASSERT_SIZE(TTextLine, 0x20);
