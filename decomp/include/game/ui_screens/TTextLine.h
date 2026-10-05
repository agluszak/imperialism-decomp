#pragma once

#include "game/ui_core/TControl.h" // TextStyle
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e4c0
class TTextLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTextLine)
  virtual ~TTextLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x570500

  CString captionText; // 0x10
  // Font/theme preset consumed by CreateFontFromPresetAndAttachRegionHandle et al.
  TextStyle styleDescriptor14; // 0x14
  // Passed directly to TStaticText::SetJustification.
  short textAlignmentCode; // 0x1e

  TTextLine();
  void ITextLine(short rowArg, short colArg, int* bounds, short styleGroupCode,
                                    short styleIndex);
  // 0x570440 -- copy-assign the 10-byte packed style descriptor.
  void SetTextLineStyleDescriptor(const TextStyle* descriptor);
  void SetTextLineStyleComponents(short fontCode, short styleCode, short sizeCode,
                                  unsigned char red, unsigned char green,
                                  unsigned char blue); // 0x570470
  // 0x5704e0
  void SetTheJustification(short value);
  void SetCaptionText(CString* caption); // 0x00570420
};

ASSERT_SIZE(TTextLine, 0x20);
