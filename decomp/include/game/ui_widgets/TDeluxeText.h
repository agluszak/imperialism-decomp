#pragma once

#include "compat.h"

#include "game/ui_core/TTEView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006406d8
class TDeluxeText : public TTEView {
public:
  DECLARE_DYNCREATE(TDeluxeText)
  virtual ~TDeluxeText() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void EnableEditing(bool enable);
  virtual void LoadTextResource(short stringId);
  virtual void SetTextStyle(const TextStyle& style, bool refreshNow);
  virtual void SetTextStyle(int fontStyleFlags, int pointSize, int themeCode);
  virtual void BuildCityViewProductionControls_Impl(short codeGroup, short stringIndex);
  virtual void SetEntryText(CString* text, bool notifyFlag);
  virtual void UpdateTextEntrySharedString(CString* text);
  virtual void StuffBuffer(const char* textChars, int textLength);
  virtual short CenterVertically(bool refreshNow);
  COLORREF textColor;
  COLORREF shadowTextColor;
  bool dropShadowEnabled;

  TDeluxeText();

  void IDeluxeText(TView* panel, int* offsetLayout, int* sizeLayout, RECT* insetRect,
                   TextStyle* style, short styleWord90);
};
ASSERT_SIZE(TDeluxeText, 0xa4);
