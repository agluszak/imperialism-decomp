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

  // CString caption, populated from TSimMgr::GetString(styleGroupCode, styleIndex - 1, ...)
  // by SetTextLineRowBoundsAndStyle when a valid style group is supplied.
  CString captionText10; // 0x10
  // Font/theme preset consumed by CreateFontFromPresetAndAttachRegionHandle et al.
  TextStyle styleDescriptor14; // 0x14
  // Sentinel-initialized (0xfffe) by SetTextLineRowBoundsAndStyle; exact semantics
  // (e.g. a "no selection" index) not yet confirmed from a distinct evidentiary call site.
  short field1e; // 0x1e

  TTextLine();
  // 0x570390 -- extends TLineData::SetLineDataRowAndBounds with an optional localized
  // caption (styleGroupCode != -1) and an unconditional style-descriptor rebuild.
  void SetTextLineRowBoundsAndStyle(short rowArg, short colArg, int* bounds, short styleGroupCode,
                                    short styleIndex);
  // 0x570440 -- copy-assign the 10-byte packed style descriptor.
  void SetTextLineStyleDescriptor(const TextStyle* descriptor);
  // 0x5704e0
  void SetField1E(short value);
  void SetCaptionText(CString* caption); // 0x00570420
};

ASSERT_SIZE(TTextLine, 0x20);
