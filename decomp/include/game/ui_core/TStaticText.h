#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/core/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString* text;             // 0x84
  int stringResourceGroupId; // 0x88, -1 means no string resource
  int stringResourceIndex;   // 0x8c
  short textAlignmentCode;   // 0x90, -2 left, 1 center, -1 right while drawing
  short textOptionFlags; // 0x92

  TStaticText();
  TStaticText(const TStaticText& source); // 0x0048f9d0
  virtual ~TStaticText() override;

  void CopyViewStateFromSource(TView* source);

  void IStaticText(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam6,
                   int layoutParam7, short stringResourceGroup, short stringResourceIndex);

  DECLARE_DYNCREATE(TStaticText)

  TObject* ShallowClone() override;     // 0x20 0x48fc00
  void Draw(RECT* rectBuffer) override; // 0x110 0x48ffb0

  void SetText(CString* text);

  virtual void SetJustification(short alignmentCode,
                                               bool refreshFlag); // 0x1c4 0x48ff70
  virtual void SetTextAndMaybeRefresh(CString* sharedString,
                                      bool refreshNow); // 0x1c8 0x48fe60
  virtual void SetTextWithStrListID(short stringResourceGroup, short stringResourceIndex,
                                         bool refreshNow); // 0x1cc 0x48fed0
  virtual void CopyTextTo(CString* out);                   // 0x1d0 0x4294d0
  virtual void ImageText(const char* textChars, int textLength, RECT* rect,
                               short alignmentCode); // 0x1d4 0x4900a0
};
ASSERT_SIZE(TStaticText, 0x94);
