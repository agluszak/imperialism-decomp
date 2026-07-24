#pragma once

#include "compat.h"

#include "game/ui_core/TTEView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006406d8
class TDeluxeText : public TTEView {
public:
  DECLARE_DYNCREATE(TDeluxeText)
  virtual ~TDeluxeText() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;        // slot 0x37 0x5b6060
  virtual void Draw(RECT* rectBuffer) override;       // slot 0x44 0x5b6170
  virtual void SetSelectedFlagAndState(char param_1); // slot 0x76 0x5b60a0
  // Loads the localized UI string `stringId` from the module cache and assigns it
  // via UpdateTextEntrySharedStringAndMaybeNotify (verified 1-arg thiscall, RET 4;
  // the old InitializeTechHistoryViewTitleAndMapKeyControls name was junk and the
  // declaration had dropped the argument).
  virtual void SetTextFromUiStringResourceId(short stringId); // slot 0x77 0x5b60d0
  virtual void SetTextStyle(const TextStyle& style,
                            unsigned char refreshNow); // slot 0x79 0x5b62a0
  // VC5 emits an overload set's virtual entries in reverse declaration order, so this
  // declaration follows the reference overload while occupying the preceding slot.
  // The Mac build used shorts, but the Windows body forwards all three full dword
  // arguments without sign extension; keep the verified Windows ABI here.
  virtual void SetTextStyle(int fontStyleFlags, int pointSize,
                            int themeCode); // slot 0x78 0x5b62e0
  virtual void BuildCityViewProductionControls_Impl(short codeGroup,
                                                    short stringIndex); // slot 0x7a 0x5b64e0
  virtual void UpdateTextEntrySharedStringAndMaybeNotify(CString* text,
                                                         char notifyFlag); // slot 0x7b 0x5b64a0
  virtual void UpdateTextEntrySharedString(CString* text);                 // slot 0x7c 0x5b6480
  // Assign the entry text from a raw char pointer; the length argument is accepted but
  // unused by the body (ret 8 proves the two-arg shape; renamed from the provisional
  // Helper_Uses_ConstructSharedStringFromCStrOrResourceId_At005b6360).
  virtual void SetTextEntryFromChars(const char* textChars,
                                     int textLength); // slot 0x7d 0x5b6360
  // Vertically centers the wrapped text when its measured height is smaller than the
  // control frame, then optionally invalidates the control.
  virtual short CenterVertically(unsigned char refreshNow); // slot 0x7e 0x5b63e0
  // field94/field95/padding96 moved to the base TTEView (its RTTI object size is
  // 0x98; TDeluxeText's own fields start at 0x98 — see TTEView.h).
  COLORREF textColor98;       // +0x98
  COLORREF shadowTextColor9C; // +0x9c
  bool dropShadowEnabledA0;   // +0xa0
  unsigned char paddingA1[3]; // +0xa1

  TDeluxeText();

  // Mac-style second-phase init: forwards to TTEView::ITEView with the
  // fixed (0, ..., 5, 5, ..., 0, 1) filler args, copies style->textColor into
  // textColor98, and clears the selected flag via the slot-0x76 virtual.
  // 0x5b5ff0, __thiscall, RET 0x18.
  void IDeluxeText(TView* panel, int* offsetLayout, int* sizeLayout, RECT* insetRect,
                   TextStyle* style, short styleWord90);
};
ASSERT_SIZE(TDeluxeText, 0xa4);
