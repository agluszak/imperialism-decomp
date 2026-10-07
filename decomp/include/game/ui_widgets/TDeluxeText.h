#pragma once

#include "compat.h"

#include "game/ui_core/TTEView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006406d8
class TDeluxeText : public TTEView {
public:
  DECLARE_DYNCREATE(TDeluxeText)
  virtual ~TDeluxeText() override;               // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;   // slot 0x37 0x5b6060
  virtual void Draw(RECT* rectBuffer) override;  // slot 0x44 0x5b6170
  virtual void EnableEditing(bool enable);       // slot 0x76 0x5b60a0
  virtual void LoadTextResource(short stringId); // slot 0x77 0x5b60d0
  virtual void SetTextStyle(const TextStyle& style,
                            bool refreshNow); // slot 0x79 0x5b62a0
  virtual void SetTextStyle(int fontStyleFlags, int pointSize,
                            int themeCode); // slot 0x78 0x5b62e0
  virtual void BuildCityViewProductionControls_Impl(short codeGroup,
                                                    short stringIndex); // slot 0x7a 0x5b64e0
  virtual void UpdateTextEntrySharedStringAndMaybeNotify(CString* text,
                                                         bool notifyFlag); // slot 0x7b 0x5b64a0
  virtual void UpdateTextEntrySharedString(CString* text);                 // slot 0x7c 0x5b6480
  virtual void SetTextEntryFromChars(const char* textChars,
                                     int textLength); // slot 0x7d 0x5b6360
  virtual short CenterVertically(bool refreshNow);    // slot 0x7e 0x5b63e0
  COLORREF textColor;                                 // +0x98
  COLORREF shadowTextColor;                           // +0x9c
  bool dropShadowEnabled;                             // +0xa0
  unsigned char paddingA1[3];                         // +0xa1

  TDeluxeText();

  void IDeluxeText(TView* panel, int* offsetLayout, int* sizeLayout, RECT* insetRect,
                   TextStyle* style, short styleWord90);
};
ASSERT_SIZE(TDeluxeText, 0xa4);
