#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/core/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString* text;
  int stringResourceGroupId; // -1 means no string resource
  int stringResourceIndex;
  short textAlignmentCode; // -2 left, 1 center, -1 right while drawing
  short textOptionFlags;

  TStaticText();
  TStaticText(const TStaticText& source);
  virtual ~TStaticText() override;

  void CopyViewStateFromSource(TView* source);

  void IStaticText(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam6,
                   int layoutParam7, short stringResourceGroup, short stringResourceIndex);

  DECLARE_DYNCREATE(TStaticText)

  TObject* ShallowClone() override;
  void Draw(RECT* rectBuffer) override;

  void SetText(CString* text);

  virtual void SetJustification(short alignmentCode, bool refreshFlag);
  virtual void SetTextAndMaybeRefresh(CString* sharedString, bool refreshNow);
  virtual void SetTextWithStrListID(short stringResourceGroup, short stringResourceIndex,
                                    bool refreshNow);
  virtual void CopyTextTo(CString* out);
  virtual void ImageText(const char* textChars, int textLength, RECT* rect, short alignmentCode);
};
ASSERT_SIZE(TStaticText, 0x94);
