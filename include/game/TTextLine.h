#pragma once

#include "game/TControl.h" // TextStyle
#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e4c0
class TTextLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTextLine)
  virtual ~TTextLine() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x570500
  // slot 0x0b OrphanRetStub_0056f480 inherited unchanged (0x56f480)

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
};

ASSERT_SIZE(TTextLine, 0x20);
