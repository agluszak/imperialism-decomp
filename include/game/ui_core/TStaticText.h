#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/ui_screens/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  // Heap-allocated (`new CString()` in the ctor, freed in the dtor) — not an
  // embedded CString. Confirmed by the ctor/dtor disassembly (operator_new(4)
  // + CString::CString/~CString + operator_delete) and by
  // CopyTextTo/SetTextAndMaybeRefresh,
  // which both dereference it once more than an embedded value would need.
  CString* text;             // 0x84
  int stringResourceGroupId; // 0x88, -1 means no string resource
  int stringResourceIndex;   // 0x8c
  short textAlignmentCode;   // 0x90, -2 left, 1 center, -1 right while drawing
  // Additional text option written by TJoinSelectorDialog for its native edit control.
  // No reader has yet distinguished the individual flag bits.
  short textOptionFlags; // 0x92

  TStaticText();
  TStaticText(const TStaticText& source); // 0x0048f9d0
  virtual ~TStaticText() override;

  void CopyViewStateFromSource(TView* source);

  void InitializeTextEntryBaseAndOptionalStringResource(TView* panel, int* offsetLayout,
                                                        int* sizeLayout, int layoutParam6,
                                                        int layoutParam7, short stringResourceGroup,
                                                        short stringResourceIndex);

  DECLARE_DYNCREATE(TStaticText)

  TObject* ShallowClone() override;     // 0x20 0x48fc00
  void Draw(RECT* rectBuffer) override; // 0x110 0x48ffb0

  // 0x486290 — non-virtual convenience: qualified forward to
  // SetTextAndMaybeRefresh(text, 0).
  void SetText(CString* text);

  // TStaticText's five new virtuals beyond TControl (which ends at byte 0x1c0).
  // None of these five are ever called for their return value anywhere in the
  // binary, and none of the bodies deliberately compute one (Ghidra's
  // "undefined" reflects an untracked/incidental AL, not a real result) — so
  // all five are modeled as void, matching observed behavior exactly.
  virtual void SetTextAlignmentAndMaybeRefresh(short alignmentCode,
                                               char refreshFlag); // 0x1c4 0x48ff70
  virtual void SetTextAndMaybeRefresh(CString* sharedString,
                                      char refreshNow); // 0x1c8 0x48fe60
  virtual void SetTextFromStringResource(short stringResourceGroup, short stringResourceIndex,
                                         char refreshNow); // 0x1cc 0x48fed0
  virtual void CopyTextTo(CString* out);                   // 0x1d0 0x4294d0
  virtual void DrawTextAligned(const char* textChars, int textLength, RECT* rect,
                               short alignmentCode); // 0x1d4 0x4900a0
};
ASSERT_SIZE(TStaticText, 0x94);
