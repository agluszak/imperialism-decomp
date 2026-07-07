#pragma once

#include "game/TControl.h"
#include "game/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  // Heap-allocated (`new CString()` in the ctor, freed in the dtor) — not an
  // embedded CString. Confirmed by the ctor/dtor disassembly (operator_new(4)
  // + CString::CString/~CString + operator_delete) and by
  // AssignSharedStringFromField84/AssignTextSharedRefIfChangedAndMaybeInvalidate,
  // which both dereference it once more than an embedded value would need.
  CString* text; // 0x84
  void* field88; // 0x88
  int field8C;   // 0x8c
  short field90; // 0x90

  TStaticText();
  virtual ~TStaticText() override;

  void CopyViewStateFromSource(TView* source);

  void InitializeTextEntryBaseAndOptionalStringResource(TControl* panel, int* offsetLayout,
                                                        int* sizeLayout, int layoutParam6,
                                                        int layoutParam7, short stringResourceGroup,
                                                        short stringResourceIndex);

  DECLARE_DYNCREATE(TStaticText)

  TObject* ShallowClone() override;                 // 0x20 0x48fc00
  void ApplyRectSlot110(RECT* rectBuffer) override; // 0x110 0x48ffb0

  // 0x486290 — non-virtual convenience: qualified forward to
  // AssignTextSharedRefIfChangedAndMaybeInvalidate(text, 0).
  void UpdateTextEntrySharedStringIfChanged(CString* text);

  // TStaticText's five new virtuals beyond TControl (which ends at byte 0x1c0).
  // None of these five are ever called for their return value anywhere in the
  // binary, and none of the bodies deliberately compute one (Ghidra's
  // "undefined" reflects an untracked/incidental AL, not a real result) — so
  // all five are modeled as void, matching observed behavior exactly.
  virtual void SetTextThemeCodeAndMaybeRefresh(short themeCode,
                                               char refreshFlag); // 0x1c4 0x48ff70
  virtual void AssignTextSharedRefIfChangedAndMaybeInvalidate(CString* sharedString,
                                                              char refreshNow); // 0x1c8 0x48fe60
  virtual void LoadUiStringAndDispatchViaVslot1C8(short stringResourceGroup,
                                                  short stringResourceIndex); // 0x1cc 0x48fed0
  virtual void AssignSharedStringFromField84(CString* out);                   // 0x1d0 0x4294d0
  virtual void RenderControlStateTextBySelectionCode(const char* textChars, int textLength,
                                                     RECT* rect,
                                                     short alignmentCode); // 0x1d4 0x4900a0
};
